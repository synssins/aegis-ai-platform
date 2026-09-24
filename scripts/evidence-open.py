#!/usr/bin/env python3
"""Open an Aegis evidence handoff bundle (.aegis-evidence). Standalone: needs only `pip install cryptography`.
Usage: python3 evidence-open.py <bundle> [--out record.json]   (prompts for the key that was provided separately)"""
import getpass, hashlib, json, sys
from cryptography.fernet import Fernet, InvalidToken
if len(sys.argv) < 2: raise SystemExit(__doc__)
b = json.load(open(sys.argv[1], encoding="utf-8"))
if b.get("format") != "aegis-evidence-handoff-v1": raise SystemExit("not an Aegis evidence handoff bundle")
key = getpass.getpass("Decryption key (provided separately): ").strip()
try: rec = json.loads(Fernet(key.encode()).decrypt(b["ciphertext"].encode()))
except (InvalidToken, ValueError): raise SystemExit("wrong key or corrupted bundle")
body = {k: v for k, v in rec.items() if k not in ("prev_hash", "hash")}
ok = hashlib.sha256((rec["prev_hash"] + json.dumps(body, sort_keys=True, ensure_ascii=False)).encode()).hexdigest() == rec["hash"] == b["chain_hash"]
print(f"record {rec['id']}  sealed {rec['ts']}  exported {b['exported']} by {b['exported_by']}\nintegrity: {'VERIFIED' if ok else 'FAILED'} (hash {rec['hash'][:16]}…, previous {rec['prev_hash'][:16]}…)")
out = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else None
if out: json.dump(rec, open(out, "w", encoding="utf-8"), indent=1, ensure_ascii=False); print("written", out)
else: print(json.dumps(rec, indent=1, ensure_ascii=False))
