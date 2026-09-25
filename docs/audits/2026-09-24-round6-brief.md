# Adversarial audit — round 6 brief (prepared 2026-09-24, to be run next session)

Rounds 1–5 (`docs/tests/agy-vetoguard-review-*.md`) covered VetoGuard through rev 2.9 and the hub v3 login; round 5
closed with no findings. Everything below shipped **after** that and has had only the acceptance suite (85/85,
`docs/tests/*.json`) and the author's own tests. It is the scope for round 6, reviewer = Gemini via `agy`
(`agy -p "<prompt>" --add-dir /data/ai-unified --output-format json`; if Gemini's filter refuses a "security review"
wording, rephrase as "robustness and correctness review of an access-control layer"). Fix → re-review → repeat until
a round ends clean, as before.

**Update 2026-09-24 night:** a separate full-repository audit (Claude) ran first — record in
`docs/audits/2026-09-24-security-audit.md`. Its stop-gap fixes touched `veto_filter.py` (now 3.0), `hub.py`,
`imagegate.py`, the Caddyfile and compose, so round 6 must also review that branch's diff and the audit's open items.
The scheduler findings (`docs/tests/agy-review-round6-01-scheduler.md`) remain open.

## Scope (files)
`caddy/hub/hub.py` (portal, accounts, sessions, device certs, chat, image gate wiring, scheduler wiring, browser
wiring), `caddy/hub/browse.py`, `caddy/hub/imagegate.py`, `caddy/hub/scheduler.py`, `caddy/conf/Caddyfile`,
`ops/aegis-watchdog.py`, `docker-compose.yml`, `scripts/comfy-workflows.py`, `proxy/veto_filter.py` (unchanged since
2.9 — confirm), `docs/HUB.md`, `docs/SAFETY.md` (claims to verify against code).

## Questions the reviewer must try to break
1. **Portal identity.** Session cookie (HMAC, epoch, device fingerprint binding), `safe_next` (open redirect), CSRF for
   JSON endpoints (`X-CSRF` header + `Sec-Fetch-Site` check on `/comfy/prompt` and uploads — is an absent header
   accepted where it should not be?), lockout, invite codes, forced password change, session lifetime "never".
2. **Grants enforcement.** Every hub-served portal route (`/chat/api/*`, `/comfy/*`, `/gallery/*`, `/hub/gallery/*`,
   `/hub/authz/comfy`) — can a `chat`-only user reach images, another user's gallery or uploads, an admin page?
   `forward_auth`: which `/comfy/*` paths bypass the hub and what can they do (ComfyUI's own API surface: `/queue`,
   `/interrupt`, `/history` POST delete, `/userdata`, `/settings`, custom-node endpoints, websocket)?
3. **Image gate.** Workflow inspection (`file_refs`, `text_inputs`, `input_refs`): can a model file or input image be
   referenced in a way the walker misses (nested lists, non-string encodings, subfolder paths, `..`, symlinks in the
   store)? `object_info` filtering completeness. Upload parsing (multipart, size cap, magic bytes, filename
   sanitising, per-user ownership registry integrity). Output gate: races between ComfyUI writing and the gate
   reading/moving; `/comfy/view` long-poll; filename reuse across prompts; batch outputs; `temp` type; can a user
   fetch another user's approved image by guessing a gallery id? Destroy-by-overwrite adequacy; evidence sealing on
   the shared hash chain (file lock vs the LiteLLM writer's thread lock).
4. **Model browser.** Thumbnail proxy (SSRF via allow-list, redirects, size cap), download path (host allow-list,
   redirects to other hosts, `.part` handling, SHA verification, symlink/`..` in names, `subdir` validation), settings
   keys at rest, NSFW toggle preconditions.
5. **Scheduler and modes.** Eviction as a denial-of-service lever between users; `note_use` accounting on aborted
   streams; wide-mode sequences through the watchdog (allow-list, ordering, protected containers, request-file
   race); `chatpool` alias behaviour during a switch; auto-revert correctness.
6. **Edge.** Caddy fetch-metadata routing for `/`; `(common)` header stripping (device identity headers) on *every*
   hub-bound route including `forward_auth`; `/comfy` redirect; `strict_sni_host insecure_off` implications.
7. **Documentation truth.** Each claim in `docs/HUB.md` → Images/Gallery, Portal chat, Scheduling, and
   `docs/SAFETY.md` → Image generation must correspond to enforced code; list any that do not.

## Method
For each finding: file:line, a concrete request/sequence that demonstrates it (neutral sentinel strings only — never
harmful content), impact, and a fix. Findings become acceptance-suite assertions (`scripts/sentinel_test.py`, phase
9 for images, a new phase 10 for portal/scheduler) before the next round.
