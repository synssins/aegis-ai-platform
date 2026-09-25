# Evidence records — retired (zero retention)

**Decision (2026-09-24, operator):** when prohibited content is attempted, the platform prevents it and keeps nothing
about it. It is better to prevent entirely than to capture data. There are no evidence records, no snippets, no
perceptual hashes and no prompt copies for vetoed requests or destroyed images.

Scope: VetoGuard, the hub (portal, image gate) and LiteLLM. Open WebUI keeps its own chat history (including refused messages) — a known open item; the portal chat does not.

What remains after a veto is a **metadata-only** audit entry in `proxy/audit/veto-audit.jsonl`: time, stage
(`pre_call`, `post_call`, `image_output`, …), reason/category code, call id, key alias, model and device fingerprint.
S4 entries (and child-safety tripwire hits) are immutable until they expire (default 730 days, minimum 90).

## Upgrading from a version that kept evidence
Versions up to VetoGuard 2.9 wrote encrypted records to `proxy/evidence/` (full request and output), optional
160-character output snippets to `proxy/audit/veto-snippets.jsonl`, failed-request rows to LiteLLM's
`LiteLLM_ErrorLogs` table, and up to 120 characters of an unreadable classifier answer into the audit log. After
upgrading:

1. On the console: `scripts/evidence-purge.sh` (runs as root; asks you to type `PURGE`) — overwrites and deletes
   the evidence and snippet files, empties `LiteLLM_ErrorLogs`, and scrubs the old classifier-answer field.
   Then recreate the litellm container so its old container log is discarded.
2. Remove `VETO_EVIDENCE_KEY` from `.env`.
3. Check backups and filesystem snapshots of `proxy/` and remove the old records there too; overwriting cannot
   guarantee erasure on SSDs or copy-on-write filesystems.

If you are under a legal preservation obligation for any existing record, take advice before step 1.

## What changed in the code
- `proxy/veto_filter.py` 3.0: `write_evidence`, `snippet`, matched-span capture and the evidence key are gone;
  `audit()` takes metadata only; unreadable classifier answers are recorded only as verdict words or a length.
- `caddy/hub/imagegate.py`: `seal_evidence` and `phash` removed; destroyed images leave only the audit entry.
- `caddy/hub/hub.py`: evidence export/download and snippet views removed; old policy keys are dropped on read.
- `proxy/config.yaml`: `disable_error_logs: true`, so LiteLLM's database keeps no failed-request text either.
- `docker-compose.yml`: no evidence mount or key in any container.
