#!/usr/bin/env bash
# CONSOLE ONLY. Decrypts sealed evidence records for law-enforcement handover, verifying the hash chain.
# Usage:  scripts/evidence-export.sh <record-id | all> <output-dir>
# Output: <output-dir>/<id>.json (plaintext), CHAIN-VERIFICATION.txt, SHA256SUMS. Directory is created 0700.
# Decryption happens inside the litellm container (it holds VETO_EVIDENCE_KEY); the key never leaves .env.
set -euo pipefail; cd "$(dirname "$0")/.."
ID="${1:?record id or 'all'}"; OUT="${2:?output dir}"
DOCKER=docker; docker info >/dev/null 2>&1 || DOCKER="sudo -n docker"
mkdir -p "$OUT" && chmod 700 "$OUT"
$DOCKER exec -i -e WANT="$ID" litellm python3 - > "$OUT/.bundle.json" <<'PY'
import base64, hashlib, json, os, sys
from cryptography.fernet import Fernet
d = os.environ.get("VETO_EVIDENCE_DIR", "/app/evidence"); want = os.environ["WANT"]
f = Fernet(base64.urlsafe_b64encode(hashlib.sha256(os.environ["VETO_EVIDENCE_KEY"].encode()).digest()))
idx = [json.loads(l) for l in open(os.path.join(d, "index.jsonl"))] if os.path.exists(os.path.join(d, "index.jsonl")) else []
ids = [e["id"] for e in idx] if want == "all" else [want]
out, prev, chain_ok = [], "GENESIS", True
for e in idx:  # walk the whole chain in order to verify integrity
    p = os.path.join(d, e["id"] + ".json.enc")
    if not os.path.exists(p):
        chain_ok = False; out.append({"id": e["id"], "error": "record file missing (expired or removed)"}); continue
    rec = json.loads(f.decrypt(open(p, "rb").read()))
    body = {k: v for k, v in rec.items() if k not in ("prev_hash", "hash")}
    h = hashlib.sha256((rec["prev_hash"] + json.dumps(body, sort_keys=True, ensure_ascii=False)).encode()).hexdigest()
    ok = (h == rec["hash"] == e["hash"]) and (rec["prev_hash"] == prev or prev == "GENESIS" and rec["prev_hash"] == "GENESIS")
    chain_ok = chain_ok and ok; prev = rec["hash"]
    if e["id"] in ids:
        out.append({**rec, "_verified": ok})
print(json.dumps({"chain_ok": chain_ok, "records": out}))
PY
python3 - "$OUT" <<'PY'
import json, sys, os, hashlib
out = sys.argv[1]; b = json.load(open(os.path.join(out, ".bundle.json")))
for r in b["records"]:
    p = os.path.join(out, r.get("id", "unknown") + ".json"); json.dump(r, open(p, "w"), indent=1, ensure_ascii=False); os.chmod(p, 0o600)
with open(os.path.join(out, "CHAIN-VERIFICATION.txt"), "w") as f:
    f.write(f"hash chain intact: {b['chain_ok']}\nrecords exported: {len(b['records'])}\nverified individually: {[r.get('_verified') for r in b['records']]}\n")
with open(os.path.join(out, "SHA256SUMS"), "w") as f:
    for n in sorted(os.listdir(out)):
        if n.endswith(".json") and not n.startswith("."):
            f.write(hashlib.sha256(open(os.path.join(out, n), "rb").read()).hexdigest() + "  " + n + "\n")
os.unlink(os.path.join(out, ".bundle.json")); print(open(os.path.join(out, "CHAIN-VERIFICATION.txt")).read())
PY
echo "Exported to $OUT (0700). Handle as sensitive material."
