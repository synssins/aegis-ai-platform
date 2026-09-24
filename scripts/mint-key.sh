#!/usr/bin/env bash
# Mint / list / revoke LiteLLM virtual keys. CONSOLE ONLY — uses the master key from .env.
# Usage:
#   mint-key.sh mint <alias> [models=mixtral] [rpm=60] [tpm=200000]
#   mint-key.sh list
#   mint-key.sh revoke <alias>
# The generated key is printed ONCE. Record the alias (never the key) in docs/CHANGELOG.md.
set -euo pipefail
cd "$(dirname "$0")/.."
envval() { grep -E "^$1=" .env | head -1 | cut -d= -f2- | sed -E "s/^'(.*)'$/\1/; s/^\"(.*)\"$/\1/"; }
MK=$(envval LITELLM_MASTER_KEY); [ -n "$MK" ] || { echo "LITELLM_MASTER_KEY missing in .env" >&2; exit 1; }
DOCKER=docker; docker info >/dev/null 2>&1 || DOCKER="sudo -n docker"
# LiteLLM image ships no curl; drive its API with the container's own python.
api() { $DOCKER exec -i -e MK="$MK" -e M="$1" -e P="$2" litellm python3 -c '
import json,os,sys,urllib.request
body=sys.stdin.read().encode() or None
req=urllib.request.Request("http://localhost:4000"+os.environ["P"],data=body,method=os.environ["M"],
    headers={"Authorization":"Bearer "+os.environ["MK"],"Content-Type":"application/json"})
try:
    r=urllib.request.urlopen(req,timeout=30); print(r.read().decode())
except urllib.error.HTTPError as e: print(json.dumps({"http_error":e.code,"body":e.read().decode()[:400]})); sys.exit(1)
'; }
case "${1:-}" in
  mint)
    alias="${2:?alias required}"; models="${3:-mixtral}"; rpm="${4:-60}"; tpm="${5:-200000}"
    mj=$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1].split(",")))' "$models")
    printf '{"key_alias":"%s","models":%s,"rpm_limit":%s,"tpm_limit":%s,"metadata":{"minted_by":"console","at":"%s"}}' \
      "$alias" "$mj" "$rpm" "$tpm" "$(date -u +%FT%TZ)" | api POST /key/generate \
      | python3 -c 'import sys,json; d=json.load(sys.stdin); print("KEY (shown once):", d["key"]); print("alias:", d.get("key_alias"), "models:", d.get("models"), "rpm:", d.get("rpm_limit"))'
    ;;
  list)   printf '' | api GET '/key/list?return_full_object=true&page=1&size=100' \
            | python3 -c 'import sys,json
for k in json.load(sys.stdin).get("keys",[]):
    print(str(k.get("key_alias")).ljust(20), "models=", k.get("models"), "rpm=", k.get("rpm_limit"), "created=", (k.get("created_at") or "")[:19])' ;;
  revoke) printf '{"key_aliases":["%s"]}' "${2:?alias}" | api POST /key/delete ;;
  *) sed -n '2,7p' "$0"; exit 1 ;;
esac
