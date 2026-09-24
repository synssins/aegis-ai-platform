# Evidence records — for operators and for law enforcement

This page explains what a sealed evidence record is, how it is protected, and how a recipient opens and verifies
one. It uses only public, standard building blocks so that nothing here requires trusting this project's code.

## What is captured, and when
A record is created only when the safety gate refuses a request or a response for the **serious class** —
by default Llama Guard category **S4** (see the Llama Guard 3 model card,
<https://github.com/meta-llama/PurpleLlama/blob/main/Llama-Guard3/8B/MODEL_CARD.md>) or a CSAM lexical
tripwire. Each record contains:

| Field | Meaning |
|---|---|
| `id`, `ts` | record id and UTC timestamp |
| `stage`, `reason`, `detail`, `categories` | which gate fired (input/output), why, category codes with names |
| `matches` | for tripwire hits: the pattern and the **exact matched text span** |
| `request` | the full request as received: messages/prompt/input/system/tool schemas |
| `output` | the model's text output, if the veto was on the output side |
| `model`, `call_id`, `key_alias` | which model, the proxy call id, and the API key alias (a cryptographic identity: the key had to be presented) |
| `client_ip`, `user_agent`, `device_fingerprint` | network claims (spoofable) and, when device certificates are in use, the SHA-256 fingerprint of the client certificate (not spoofable without the device's private key) |
| `prev_hash`, `hash` | tamper-evidence chain (below) |

**Images:** for image generation, a flagged image is deleted immediately and never stored, encrypted or not.
Evidence for images is the prompt, metadata, verdict and a perceptual hash (PDQ,
<https://github.com/facebook/ThreatExchange/tree/main/pdq>) that lets investigators match against known material
without the platform holding contraband.

## How records are protected at rest
- Encrypted with **Fernet** (public spec: <https://github.com/fernet/spec/blob/master/Spec.md> — AES-128-CBC with
  HMAC-SHA256, implemented by the `cryptography` package, <https://cryptography.io/en/latest/fernet/>). Key:
  SHA-256 of the platform's `VETO_EVIDENCE_KEY`, base64url-encoded.
- **Hash-chained:** `hash = SHA-256(prev_hash + canonical_json(record without prev_hash/hash))`, canonical JSON
  being `json.dumps(record, sort_keys=True, ensure_ascii=False)`. The first record's `prev_hash` is `GENESIS`.
  Removing or altering any record breaks every later link.
- Stored root-only in `proxy/evidence/`; a plaintext `index.jsonl` holds metadata only (no content). The admin UI
  lists ids and hashes and never decrypts.
- Retention: minimum 90 days, default 730; expiry is audited.

## Handing a record to law enforcement
From the hub (Safety → Audit log → *Export for handoff*): the record is re-encrypted with a **fresh, single-use
Fernet key**; the operator downloads `<id>.aegis-evidence` and is shown the key **once**. File and key must
travel by **separate channels**. The export and the download are recorded in the administrative audit log.

### Opening a handoff bundle (recipient)
Requirements: Python 3 and the `cryptography` package (`pip install cryptography`).
```
python3 evidence-open.py <id>.aegis-evidence --out <id>.json
```
The tool prompts for the key, decrypts, recomputes the record hash and compares it with the hash embedded in the
bundle and in the platform's chain, and prints `integrity: VERIFIED` or `FAILED`. `evidence-open.py` is in this
repository under `scripts/` and is ~25 lines: it can be read in full before use.

Bundle format (`aegis-evidence-handoff-v1`):
```json
{"format": "aegis-evidence-handoff-v1", "id": "...", "exported": "...", "exported_by": "...",
 "chain_hash": "<sha256>", "prev_hash": "<sha256|GENESIS>", "chain_verified_at_export": true,
 "ciphertext": "<Fernet token of the record JSON>"}
```
Verifying by hand without the tool: base64url-decode nothing — the Fernet token is opened with the key using any
Fernet implementation; then `sha256(prev_hash + json.dumps(record_without_prev_hash_and_hash, sort_keys=True,
ensure_ascii=False))` must equal `hash` and `chain_hash`.

### Bulk export (console)
`scripts/evidence-export.sh <id|all> <outdir>` decrypts inside the platform, verifies the whole chain, and writes
plaintext JSON + `CHAIN-VERIFICATION.txt` + `SHA256SUMS` into a 0700 directory.

## Notes for the operator
- Keep an offline copy of `VETO_EVIDENCE_KEY`. Without it, records are unreadable.
- Retention of prompt text for the serious class is standard practice for platforms; confirm the specifics for
  your jurisdiction with counsel before relying on it.
- Treat exported bundles as sensitive material.
