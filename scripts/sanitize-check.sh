#!/usr/bin/env bash
# Pre-commit guard: refuse to commit anything machine- or operator-specific, and never secrets/data.
# Private patterns are DERIVED at run time (nothing identifying is stored in a file):
#   - AEGIS_LAN_IP (and its /24 prefix) and ACME_EMAIL from .env
#   - this host's hostname and the committing user's login name
#   - optional extra regexes, one per line, in .sanitize-patterns (gitignored) if you create it
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
PATS=$(mktemp); trap 'rm -f "$PATS"' EXIT
if [ -f .env ]; then
  ip=$(grep -E '^AEGIS_LAN_IP=' .env | cut -d= -f2- | tr -d '[:space:]' || true)
  [ -n "$ip" ] && { printf '%s\n' "${ip//./\\.}"; printf '%s\n' "$(echo "$ip" | cut -d. -f1-3 | sed 's/\./\\./g')\\."; } >> "$PATS"
  em=$(grep -E '^ACME_EMAIL=' .env | cut -d= -f2- | tr -d '[:space:]' || true)
  [ -n "$em" ] && [ "$em" != "CHANGE_ME@example.com" ] && printf '%s\n' "${em//./\\.}" >> "$PATS"
fi
printf '%s\n' "$(hostname)" "$(id -un)" >> "$PATS"
# public hostname configured from the hub (root-only state file) and its registrable domain
hn=$(sudo -n python3 -c "import json;print(json.load(open('caddy/hub/state/hub.json')).get('hostname',''))" 2>/dev/null || true)
[ -n "$hn" ] && { printf '%s\n' "${hn//./\\.}"; printf '%s\n' "$(echo "$hn" | awk -F. '{print $(NF-1)"\\."$NF}')"; } >> "$PATS"
[ -f .sanitize-patterns ] && cat .sanitize-patterns >> "$PATS"
fail=0
while IFS= read -r file; do
  if git show ":$file" | grep -nEi -f "$PATS" >/dev/null 2>&1; then
    echo "sanitize-check: BLOCKED — $file contains a private pattern:"
    git show ":$file" | grep -nEi -f "$PATS" | head -5 | sed 's/^/    /'
    fail=1
  fi
done < <(git diff --cached --name-only --diff-filter=ACMR)
if git diff --cached --name-only | grep -qE '(^|/)\.env$|\.sanitize-patterns$|(^|/)audit/|(^|/)db/|caddy/data/|caddy/sites-enabled/|(^|/)backup/'; then
  echo "sanitize-check: BLOCKED — attempted to stage a secret/data path"; fail=1
fi
exit $fail
