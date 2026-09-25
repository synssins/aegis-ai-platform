#!/usr/bin/env bash
# CONSOLE ONLY — one-time cleanup for the zero-retention change (2026-09-24). Run as root (re-executes with sudo).
#
# Earlier versions kept content from vetoed requests in four places. The platform no longer writes to any of them.
# This script removes what earlier versions left behind:
#   1. proxy/evidence/                     sealed "evidence" records (full request/output) + handoff bundles
#   2. proxy/audit/veto-snippets.jsonl     optional 160-character flagged-output snippets
#   3. LiteLLM_ErrorLogs table (litellm-db) failed-request rows, whose request_kwargs can hold the prompt
#   4. old guard_verdict_unparseable audit lines, whose got='...' could echo up to 120 characters of user text
#      (the line is kept; only that field is replaced)
# Files are overwritten, then deleted. It cannot be undone.
#
# If you are under a legal preservation obligation for any of these records, stop and take advice first.
set -euo pipefail; cd "$(dirname "$0")/.."
[ "$(id -u)" -eq 0 ] || exec sudo "$0" "$@"
DOCKER=docker

files=()
if [ -e proxy/evidence ]; then
  while IFS= read -r -d '' f; do files+=("$f"); done < <(find proxy/evidence -type f -print0)
fi
[ -f proxy/audit/veto-snippets.jsonl ] && files+=("proxy/audit/veto-snippets.jsonl")
errlogs=$($DOCKER exec litellm-db psql -U litellm -d litellm -tAc 'select count(*) from "LiteLLM_ErrorLogs"' 2>/dev/null || echo "?")
audits=$(ls proxy/audit/veto-audit.jsonl* 2>/dev/null | wc -l)

echo "Found: ${#files[@]} evidence/snippet file(s); LiteLLM_ErrorLogs rows: ${errlogs:-0}; ${audits} veto audit file(s) to scrub."
read -r -p "Type PURGE to continue: " ok; [ "$ok" = "PURGE" ] || { echo "aborted"; exit 1; }

for f in "${files[@]}"; do
  shred -u -n 1 -z "$f" 2>/dev/null || { dd if=/dev/zero of="$f" bs=1M count=$(( ($(stat -c %s "$f") >> 20) + 1 )) conv=notrunc status=none; rm -f "$f"; }
done
[ -e proxy/evidence ] && find proxy/evidence -depth -type d -empty -delete
echo "1-2: removed ${#files[@]} file(s)"

if [ "$errlogs" != "?" ]; then
  $DOCKER exec litellm-db psql -U litellm -d litellm -qc 'TRUNCATE "LiteLLM_ErrorLogs"' && echo "3: LiteLLM_ErrorLogs emptied"
else
  echo "3: litellm-db not running — start it and run this script again to empty LiteLLM_ErrorLogs"
fi

for f in proxy/audit/veto-audit.jsonl*; do
  [ -f "$f" ] || continue
  case "$f" in *.lock) continue;; esac
  python3 - "$f" <<'PY'
import json, re, sys, os
p = sys.argv[1]; out = []; n = 0
for line in open(p, encoding="utf-8"):
    try: e = json.loads(line)
    except ValueError: out.append(line); continue
    if e.get("reason") in ("guard_verdict_unparseable",) and "got=" in str(e.get("detail", "")):
        e["detail"] = re.sub(r"got=.*?(?= expected=|$)", "got='<scrubbed>'", str(e["detail"]), count=1, flags=re.S); n += 1
    out.append(json.dumps(e) + "\n")
tmp = p + ".scrub"
open(tmp, "w", encoding="utf-8").writelines(out); os.chmod(tmp, os.stat(p).st_mode & 0o777); os.replace(tmp, p)
print(f"4: {p}: scrubbed {n} line(s)")
PY
done

echo
echo "Also:"
echo " - remove VETO_EVIDENCE_KEY from .env"
echo " - recreate the litellm container (docker compose up -d --force-recreate litellm) so its old container log, which"
echo "   repeated the audit lines, is discarded"
echo " - remove old copies of proxy/ from backups and snapshots; on SSDs and copy-on-write filesystems overwriting"
echo "   cannot guarantee the old blocks are gone"
