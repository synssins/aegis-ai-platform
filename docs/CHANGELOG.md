# Changelog

All significant changes to the platform are recorded here. Every entry must name the files touched, the reason, who/what made the change, and how it was verified. Security-relevant changes must link an audit record in `docs/audits/`.

## 2026-09-24 (late afternoon) — VetoGuard 2.6 → 2.7 (Agy rounds 4–5); snippet diagnostics; first real-world false positive

- **Home Assistant false positive (15:16 UTC):** key `home-assistant-test`, user "Good morning." → reply withheld, `post_call_stream classifier S1`. Llama Guard 1B scored 0/20 false positives on generic assistant exchanges, so the flag was content-specific (HA replies recite device/lock/alarm state). Diagnosis is blocked by the no-content audit design → added an **admin-only, default-off** policy toggle (Safety → VetoGuard policy → Diagnostics) storing ≤ 160 chars of *flagged output* in `proxy/audit/veto-snippets.jsonl` (root-only), never for S4 / CSAM-tripwire reasons; toggling is audited + alerted; snippets are viewable in Safety → Audit log. The durable fix remains a stronger guard (8B) paired with a ≤ 20 GB main model (`gemma3:27b` is pulled).
- **VetoGuard 2.6** (round 4): new segment starts at the last user turn *with text*; tool-call args in the classifier segment; window always classified; streamed reasoning joined before scanning; base64 detection ignores format chars, 2-line wraps; SchemaBudgetExceeded handled in post-call paths; unknown multipart blocks contribute all string leaves. Round-4 #3 (hook order) rejected — verified against source.
- **VetoGuard 2.7** (round 5): oversized multipart leaves never dropped; base64 with stray non-printables cleaned and kept; system-role messages reach the classifier chunks; prefill windows classified as-is; regex scans on a dedicated 4-worker executor (saturation ⇒ refusal); streamed chunk count capped; indented base64 continuation lines accepted.
- **Agy round 6 on 2.7:** refused by Gemini's content filter — recorded as not-completed, not as clean. Likely cause of earlier intermittent empty outputs.
- **Harness:** hub tests skip with a NOTE when the `.env` hub password is stale (rotated from the UI — the operator did so at 15:18); phase 8 for round-5 classes; 76 assertions.
- **Operator actions today via the hub:** guard model set to 8B (15:02; reverted by Claude after GPU fallback), key `home-assistant-test` minted (15:03), hostname applied (14:50 → Let's Encrypt issued 13:52 UTC per cert), admin password rotated (15:18).

## 2026-09-24 (afternoon, continued) — VetoGuard 2.4 → 2.5 via Agy rounds 2–3; hub layout, pagination, password; GPU-loss safeguard

- **Adversarial loop rounds 2 and 3** (`docs/tests/agy-vetoguard-review-r2-…md`, `…-r3-…md`; JSON output mode is the reliable channel — text mode is intermittently empty). Real bugs found and fixed: base64 decoded text never reached the classifier (2.3 docstring was wrong); `n>1` streaming inspected only choice 0; fabricated earlier turns were trusted; dict-shaped responses skipped output checks; reasoning/thinking fields unscanned; unbounded audit threads; top-level system + tool schemas reached only the regex, not the classifier; JSON keys skipped; withhold chunk could leak reasoning; unscannable streamed output failed open. **VetoGuard 2.5**: whole-history tripwires + multi-turn window classification (documented trade-off vs O(n²)), fail-closed on unscannable input/output and schema-budget overflow, per-loop HTTP client, process-wide semaphore, first-blocked-verdict cancellation, flock'd audit rotation, exception text reduced. Rejected as false positive: round-2 7.3 (hook argument order) — verified against LiteLLM source.
- **Behaviour change:** a conversation containing a vetoed turn stays refused (client history is untrusted). Start a new chat after a veto. Test 3.2 updated; 3.2b asserts fresh chats work.
- **Guard model incident:** operator set `llama-guard3:8b` in the hub at 15:02; with Mixtral resident the two evict each other, Ollama then lost its GPU runner (`NVML: Unknown Error`) and fell back to CPU. Restored by `docker compose restart ollama`; policy set back to 1B (recorded). **8B requires a ≤ 20 GB main model** — `gemma3:27b` pulled as a candidate; selectable in Models → Installed. Dashboard now warns when resident models have 0 VRAM; suite asserts GPU residency (3.12). Host follow-up: NVIDIA runtime CDI mode (supervised).
- **Hub:** fixed left nav with collapsible categories (active open), independent right-pane scrolling, hidden sidebar scrollbar (touch/drag), fluid width; pagination (10/25/50/100, prev/next) on every table; Access → Admin password rotation (file-based Caddy credential, complexity policy, bcrypt 14); policy/state files written 600.
- **Tests:** 72 assertions (phases 6–7 for round-1/2 bypass classes, GPU residency).

## 2026-09-24 (afternoon) — VetoGuard 2.3 from Agy adversarial review; hub admin password rotation

- **Adversarial loop, round 1:** `docs/tests/agy-vetoguard-review-2026-09-24.md` — Agy (Gemini) reviewed VetoGuard 2.2 in permission-gated print mode; 20 findings, 7 High. All addressed in `proxy/veto_filter.py` rev 2.3: request scope now covers the latest user turn **and everything after it** (assistant prefill, tool results, tool_calls args), `system`, `prompt`, `input`, tool/function schemas; normalisation strips combining marks/format chars and maps confusables; standard + URL-safe base64 decoded and fed to the classifier; despacing removes all non-alphanumerics; streaming classifies tool-call deltas, runs tripwires on output, caps the buffer (400k chars), tolerates empty `choices`, never raises mid-stream; extraction failure is fail-closed; overlapping chunk windows (600) with bounded concurrency and `max_chunks` 100; policy reload keeps the last good policy; admin regexes are probed for catastrophic backtracking and every scan runs under a 5 s budget (timeout ⇒ refuse); exact verdict parsing; dict-shaped key attribution; audit writes off the event loop with 50 MB rotation.
- **Round 2** launched against 2.3 (results appended when available).
- **Hub: Access → Admin password.** Caddy now imports the hub credential from `caddy/sites-enabled/hub-auth.conf` (fail-closed if missing) instead of an env var; the hub rotates it (current password required, complexity policy, bcrypt cost 14, Caddy reload, audit + alert). New image `aegis/hub:2` (python:3.12-alpine + bcrypt 4.2.1). `scripts/seed-hub-auth.sh` for first install. Round-trip rotation tested.
- **Fixes:** hub → Caddy admin `Origin` must be scheme-qualified (`http://127.0.0.1:2019`); files edited via `sed -i` must be re-owned `root:<operator>` 640 or cap-dropped containers cannot read them.
- **Tests:** phase 6 (Agy round-1 bypass classes): prefill, system message, tool schema, URL-safe base64, arbitrary-delimiter despacing, combining marks, Cyrillic confusable, tool_calls-in-history, chunk budget. Suite total 61.

## 2026-09-24 (day session)

### Hub v2 admin plane, VetoGuard 2.2 policy, model pipeline, DNS-01, monitoring + apps frameworks — APPLIED. Acceptance: 52/52 (`docs/tests/…-post-v3.json`).
- **caddy/hub/hub.py v2:** dark-themed admin control centre (Overview · Safety · Models · Access · Gateway). Edits VetoGuard policy (S4 locked; classifier/fail-closed not configurable), pulls/removes/exposes models, mints/revokes API keys, sets public hostname + Cloudflare token, alert webhook. Isolation layer view-only. CSRF on every POST; every change audited to `proxy/audit/hub-audit.jsonl` and alerted.
- **proxy/veto_filter.py rev 2.2:** policy file `proxy/policy/veto-policy.json` hot-reloaded per request; default policy blocks S1–S4, S9–S11 and allows adult/legal categories; admin extra tripwires.
- **docker-compose.yml rev 3:** `mgmt` network + `modeld` pull-only Ollama (apps never fetch models); caddy joins `backend`/`mgmt` for the hub; litellm `STORE_MODEL_IN_DB=True`; profiles `monitoring` (prometheus v3.5.0, node-exporter v1.9.1, dcgm-exporter 4.2.3, grafana 11.6.0 at `/grafana`, provisioned datasource + GPU/host dashboard) and `apps` (fish-speech, comfyui placeholders). Shared `x-hardened` anchor.
- **caddy/Caddyfile rev 3 + caddy/build/Dockerfile:** local Caddy build with `caddy-dns/cloudflare`; routes `/grafana`, `/tts`, `/comfy` (hard 503 gate). Public hostname template uses DNS-01 — the box stays private.
- **Guard model decision (measured):** 8B evicts Mixtral on 2× T4 (10 s + 26 s per request) and is 14–21 s on CPU; 1B stays (0.12 s). Numbers in `docs/HUB.md`. 8B becomes viable with a ≤ 20 GB main model or the guard on the Arc cards.
- **scripts/sentinel_test.py:** phase 5 — hub pages, CSRF, policy file locks/permissions, modeld isolation, ComfyUI gate, mount modes (52 assertions total).
- **scripts/pull-model.sh, mint-key.sh:** sudo fallback; LiteLLM driven via in-container Python (image has no curl).
- **docs:** HUB.md (new), ARCHITECTURE.md rewritten, ROADMAP/MIGRATION updated.
- **Agy adversarial review:** attempted in permission-gated print mode; produced no output (see report). Plan for operator-run review kept in `docs/tests/`.
- Executor: Claude Code. Operator directives incorporated: UI-only configuration after install (except isolation layer), API stays exposed for other services, adult content allowed / illegal + protected never, security first.

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
