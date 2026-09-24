# Changelog

All significant changes to the platform are recorded here. Every entry must name the files touched, the reason, who/what made the change, and how it was verified. Security-relevant changes must link an audit record in `docs/audits/`.

## 2026-09-24 (overnight run, 02:00–03:00 UTC)

### Hardened stack rev 2 — APPLIED. Acceptance: 33/33 (`docs/tests/…-post-migration.json`), baseline was 7/32.
- **Topology:** single bridge → `edge` + `backend` (`internal: true`). Ollama unreachable from OpenWebUI and the LAN; no egress.
- **docker-compose.yml:** pinned images (caddy 2.11.4, open-webui v0.11.4, ollama 0.34.3, litellm main-stable, postgres 16-alpine); `cap_drop ALL`, `no-new-privileges`, Caddy `read_only`; new services `hub` and `litellm-db`; all secrets via `.env`.
- **caddy/Caddyfile:** security headers, `Server` stripped, 32 MB body cap, `/v1` explicit allow-list (chat/completions, completions, embeddings, models) with everything else 404; `/hub` behind basic-auth; `sites-enabled/*.caddy` glob for a public hostname. File is root-owned 640, read-only in containers (console-only change).
- **caddy/hub/hub.py (new):** operator hub — service tiles, live TLS certificate status, Let's Encrypt hostname apply/remove via a fixed template + Caddy reload. Shares Caddy's network namespace; writes only `sites-enabled/domain.caddy`; audit log `proxy/audit/hub-audit.jsonl`.
- **proxy/veto_filter.py rev 2.1:** normalisation (NFKC, zero-width, whitespace, base64 decode, despaced pass), DOTALL, scans latest user turn + trailing tool results + `prompt` + `input` + multimodal parts; Llama Guard 3 (1B) classifier pre-call and post-call with buffered streaming; fail-closed; HTTP 400 `veto_triggered`; audit log `proxy/audit/veto-audit.jsonl` (no content). Removed vocabulary false-positives (`payload`, `subprocess`, `import os`, `exploit`).
- **proxy/config.yaml:** wildcard route removed; DB-backed virtual keys; admin UI disabled.
- **Keys minted (console):** aliases `openwebui` (mixtral, 120 rpm) and `sentinel-tests` (mixtral, 60 rpm). Master key rotated; OpenWebUI no longer holds it.
- **OpenWebUI:** signup off, direct connections off, web search off, Ollama API off, `WEBUI_SECRET_KEY` set, CORS pinned.
- **scripts/:** `pull-model.sh`, `mint-key.sh`, `sentinel_test.py` (33 assertions, redacts host identifiers), `sanitize-check.sh` (pre-commit; derives private patterns from `.env`/hostname/user), `install-hooks.sh`.
- **docs/:** README rewritten for public use; added ARCHITECTURE, SECURITY, ROADMAP, MIGRATION; machine-specific audit/review records moved to `docs/private/` (gitignored). LICENSE (MIT).
- **Permissions:** container data dirs root-owned 700 (required once `CAP_DAC_OVERRIDE` is dropped); `.env` 600.
- **Verification:** `docker compose config`, `caddy validate`, py_compile; full Sentinel suite; manual probes of `/`, `/hub`, `/v1`.
- **Not done (supervised only):** host sudoers/sshd changes; Agy-driven test run (permission classifier declined launching an unattended agent with permissions skipped — plan saved at `docs/tests/agy-sentinel-protocol-plan.txt` for the operator to run); monitoring stack; Intel Arc inference.
- Executor: Claude Code (overnight, container-level scope only). Architect review reconciled: `docs/private/reviews/`.

### Audit rev 1 (Claude) — findings recorded, remediation drafted, NOT applied
- Added `docs/audits/2026-09-24-security-audit-rev1.md`.
- Added `proposed/` containing hardened `docker-compose.yml`, `caddy/Caddyfile`, `proxy/veto_filter.py` (rev 2), `proxy/config.yaml`, `.env.example`, `scripts/pull-model.sh`, `MIGRATION.md`.
- Verified: `docker compose config` OK; `caddy validate` OK; VetoGuard rev 2 mechanism test (neutral sentinel) passes all evasion classes except letter-spacing (documented; classifier required).
- Live stack unchanged. Awaiting Gemini architectural review and Agy adversarial re-test.

### Initial build (Gemini prompts, executed by Agy)
- Stack stood up: LiteLLM, OpenWebUI, Caddy (`tls internal`), Ollama (2× T4). Mixtral pulled. VetoGuard rev 1. `docs/README.md` pushed to GitHub. 131k-context benchmark run directly against Ollama via a temporary host forwarder.
