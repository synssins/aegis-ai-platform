# Aegis Hub — admin control centre

`https://<LAN_IP>/hub` · user `admin`. **Own login, not basic-auth:** argon2id password hashes (64 MiB, t=3), mandatory TOTP (RFC 6238; secret Fernet-encrypted at rest with `HUB_SECRET_KEY`), HMAC-signed HttpOnly/Secure/SameSite=Strict session cookies (12 h), lockout (5 failures/user → 5 min; 20/IP → 15 min), every login/failure audited. No password is ever stored or printed anywhere: on first run (no administrator yet) `/hub` shows a **setup wizard** — choose the admin username, set a policy-checked password, enroll MFA — all in the browser. Recovery is console-only: `scripts/hub-reset-admin.sh` removes the administrator so the wizard runs again.
Dark theme. Fixed left navigation with collapsible categories (the active one open), one level of sub-pages; the right pane scrolls independently. Every table paginates (10/25/50/100 per page, prev/next) via URL query parameters.

| Category | Page | Can change | Notes |
|---|---|---|---|
| Overview | Dashboard | — | services by network, safety posture, VRAM residency, certificates, recent vetoes |
| | Metrics | — | GPU utilisation/VRAM/temperature/power per card, CPU, memory, disk, resident models, service health — Prometheus, server-rendered sparklines (last hour), auto-refresh |
| | Services | start / stop / restart (checked containers) | real container status from the host **watchdog**; caddy and hub can only be restarted; one request at a time; every watchdog response (log + errors) listed |
| Safety | VetoGuard policy | **classifier model (the one place it is chosen — saving loads it and unloads other guards)**, blocked categories, tripwires, extra regexes, **retention & evidence** (immutable categories, days; evidence categories, days), diagnostics snippet toggle (default off) | **S4 is locked on**; classifier and fail-closed cannot be disabled; every save is audited + alerted |
| | Audit log | **Clear log** (clearable entries only) | vetoes with immutable flag (🔒) and evidence-record marker; every admin action; sealed-evidence index (ids, times, categories, hashes — never content) |
| | Alerts | webhook URL | Discord/Slack/generic JSON; "Send test" |
| Models | Installed | expose / load / unload / remove; "Set as classifier" for guard-family models | expose = register in LiteLLM under a public name (through VetoGuard) — on the native chat API with real tool calls when the model advertises `tools`, text-only otherwise (capability tags shown); guard models never exposable and not loaded/unloaded by hand — their residency follows the policy choice; the active classifier cannot be removed |
| | Browse | Hugging Face + CivitAI browser (⚙ at the top right holds the registry keys and the NSFW toggle): source tabs, search, type/sort filters, list/detail/S/M/L views, local detail view with link to the source page, hardware-fit badges, **Buzz** badge for CivitAI early access, download to `comfyui/<kind>/` or pull GGUF into Ollama | previews proxied through the hub; NSFW never fetched unless the toggle is on (needs a CivitAI key, audited); `.safetensors`/`.gguf` only, SHA-256 verified when published, pickles refused; every download audited |
| | Pull | pull | via `modeld` — the only container with both internet and the model store. Apps never fetch their own |
| | Exposed to apps | unexpose (hub-created only) | models from `config.yaml` are console-managed |
| Access | API keys | mint / revoke | per-client, model-scoped, rate-limited; key shown once |
| | Devices | issue a certificate bundle (one-time download), revoke, delete (revoked only) | every action audited with the fingerprint |
| | Admin account | change password; re-enroll MFA | argon2id; policy ≥ 14 chars / 3 of 4 classes; changing the password signs out other sessions |
| Gateway | Certificates | — | live TLS probe of every served host |
| | Public hostname | hostname + Cloudflare token | writes exactly one templated site file; Let's Encrypt via DNS-01, no inbound ports |
| | Isolation | — | **read-only** view of the Caddyfile and compose network wiring |

## Public status page
`https://<LAN_IP>/status` (and `/status/api` as JSON) shows the same load/health view **without a login** — GPU/CPU/memory/disk load, models in memory, service up/down. It deliberately contains no accounts, keys, aliases or content; the acceptance suite asserts that. It is the first tile of the future portal.

## Model browser (Hub → Models → Browse)
Admin-only. Two sources today (Hugging Face, CivitAI) behind one experience; a source is a small provider in
`caddy/hub/browse.py` (search + detail + normalised item), so more registries slot in. Cards show name, author,
type, base model, downloads, likes, size, and badges: **Buzz** (CivitAI early access — downloading that version
costs Buzz), **NSFW**, **gated** (HF licence + token). Views: list, detail rows, small/medium/large thumbnails;
Hugging Face has no previews, CivitAI does. The detail view loads locally (description, previews, versions, files
with size/format/SHA-256/fit badge, trigger words) and carries the *Open on CivitAI / Hugging Face ↗* link.

Safety rules, all server-side: previews are proxied by the hub from an allow-list of registry image hosts (the
admin's browser never contacts CivitAI/HF); NSFW listings and previews are **not fetched** unless the NSFW toggle
is on — the toggle needs a CivitAI API key on file and is audited; downloads accept `.safetensors` and `.gguf`
only, refuse pickles (`.ckpt/.pt/.bin`) and anything the registry's own scans did not clear, verify SHA-256 when the
registry publishes one, write to `.part` and rename on success, and land in `comfyui/<checkpoints|loras|vae|…>/`;
GGUF pulls go through `modeld` (Models → Pull) as `hf.co/<repo>:<quant>`. Keys are Fernet-encrypted in hub
state. Fit badges compare a file to one card's memory (LLMs with a KV-cache band); guidance, not a control.

## Images and Gallery (ComfyUI behind the gate)
The portal's **Images** section is ComfyUI itself, framed at `/comfy/`, for accounts with the `images` grant. It is
reachable only through Caddy → hub: the hub handles every call that carries a prompt, a model choice or an output
(`/comfy/prompt`, `/comfy/view`, `/comfy/object_info`, `/comfy/history`); everything else (UI, websocket progress,
queue) is allowed only for a session the hub vouches for (`forward_auth`). ComfyUI has no internet egress and no
network path from the chat UI. Uploads are off until an input-image gate exists; live previews are disabled
(`--preview-method none`, temp images are never served).

Three gates on every workflow, all in `caddy/hub/imagegate.py` + `hub.py` (`_comfy_prompt`, `gate_worker`):

1. **Prompt gate** — every text input in the workflow goes through LiteLLM/VetoGuard as the user's own key
   (`portal-<user>`, one token, surface `image_prompt`): tripwires → Llama Guard → veto = 400 and the usual audit /
   evidence. Nothing is queued if this fails.
2. **File gate** — every string input that names a file in `comfyui/` is checked against the per-file attribute
   (Models → Image model store): NSFW needs the `images_nsfw` grant; unclassified is administrators only (they
   classify it there). `object_info` is filtered the same way, so users never see files they cannot use.
3. **Output gate** — when ComfyUI finishes, the hub classifies each image with the vision model chosen in Safety →
   VetoGuard policy (default `gemma3:27b`; must be resident or generation is refused up front). Verdict JSON:
   `nsfw, sexual_content, minor_present, sexual_minor, illegal, violence_gore`. Sexualised minor / illegal →
   image overwritten and unlinked, immutable veto-audit entry (S4/S3), sealed evidence (prompt texts, files,
   verdict, 64-bit DCT perceptual hash — **never the image**), alert. NSFW without the grant → destroyed, clearable
   audit (S12). Unreadable verdict or classifier error → destroyed (fail closed). Approved images are copied to
   `gallery/<user>/` and the output file wiped; `/comfy/view` serves only from the user's gallery (long-polls the
   gate for up to 25 s so the ComfyUI canvas shows the result).

**Gallery** (portal section, `images` grant): grid of the user's approved images with select-all / bulk delete.
Deletion wipes the file, its record and ComfyUI's history entry — users purge their own without review, by
operator decision. Safety → VetoGuard policy → *Administrator review of user galleries* opens Safety → Galleries
for admins (every open audited); the Gallery page tells users when review is on.

## Portal chat (portal-native)
The portal's **Chat** section is the hub's own chat, not Open WebUI. Deliberately minimal: no user settings — a model picker, a message box, and a conversation list kept in the user's browser (localStorage; nothing stored server-side). Rules, all enforced server-side in `caddy/hub/hub.py` (`_chat_stream`):

- **Model menu = exposed ∩ resident.** A model appears only if an administrator exposed it (Models → Exposed) *and* it is loaded right now. Users never load or unload anything; a request for any other model is refused (400).
- **Every turn goes through LiteLLM as the user's own virtual key** (`portal-<user>`, minted on first use with rpm/tpm limits, Fernet-encrypted in the account record, never sent to the browser). VetoGuard therefore gates every portal message exactly like the API, and vetoes/evidence name the user via the key alias. A veto shows the user *"Refused by the safety gate. This request has been logged."* — no categories.
- **No steering fields.** Only `user`/`assistant` roles (no system prompt), bounded sizes (64 turns, 32k chars each, 200k total), no `options`, `keep_alive`, `num_gpu`, tools or images pass through. The browser sends `{model, messages}` and nothing else is honoured.
- Requires a session with the `chat` grant and the page's CSRF token in `X-CSRF`; routes: `GET /chat/api/models`, `POST /chat/api/stream` (SSE relay). Each request is audited (`portal_chat`: user, model, turns, IP, device fingerprint — never content). Deleting a user deletes their key.
- **Open WebUI** remains available under the same grant as its own section ("Open WebUI", framed at `/`) for documents, voice and workspaces; it too can only speak to LiteLLM.

## Public hostname layout (no subdomains)
`/` = portal for a browser's top-level navigation (Caddy matches `Sec-Fetch-Dest: document`), Open WebUI for everything else — Open WebUI cannot run under a sub-path, so it owns the root namespace and the portal frames it at `/` same-origin. `/portal`, `/login`, `/account` = portal; `/hub` = admin; `/grafana/` = Grafana; `/status`; `/v1`. The LAN address serves Open WebUI at `/` directly. The hostname site is generated by the hub (`caddy/sites-enabled/`); the shared layout is the `(site)` snippet in `caddy/conf/Caddyfile`.

## Device identity (hard identifiers)
IP addresses and user agents are claims; a certificate is proof of possession of a key. Caddy *requests* a client certificate on every site (optional — connections without one still work) and forwards only the TLS-derived fingerprint to the hub and LiteLLM, discarding any client-supplied header of the same name. The hub issues per-device certificates (Access → Devices), binds admin sessions to the presenting fingerprint, can require a known device for admin sign-in, and records fingerprints in every login audit; VetoGuard records them in veto audit entries and evidence. Revocation is immediate at the hub (Caddy still completes the TLS handshake in request mode; the hub refuses the session). Implementation note: Caddy's fingerprint placeholder yields SHA-256 of empty input when no certificate is presented; hub and VetoGuard treat that value as "none". Client-auth policies also make Caddy enforce strict SNI/host matching, which would break access by bare IP; `strict_sni_host insecure_off` is set because both sites request the same CA. Verified end to end by test 5.22.

**Losing the device that holds the certificate.** The certificate is optional by default: an administrator signs in with password + TOTP from any device, and a session is bound to a certificate only when one was presented. So a dead PC is a non-event unless *Require a device certificate for administrators* was switched on — then no browser without a known certificate can sign in, by design, and recovery is console-only: `scripts/hub-device-recovery.sh` lifts the requirement (audited as `device_requirement_lifted`, actor `console`); sign in, issue a new certificate under Access → Devices, revoke the lost one, re-enable the requirement. Practical rule: before enabling the requirement, issue a **spare** device bundle (Access → Devices → Issue) and keep the `.p12` and its password offline (it is useless without the password and can be revoked at any time). Lost authenticator or password: `scripts/hub-reset-admin.sh` (see Recovery in `docs/OPERATIONS.md`).

**Session lifetime** is chosen on the sign-in page: 24 hours (default), 1 week, 30 days, or never (cookie re-issued up to the browser's 400-day cap). The choice is recorded in the `login_ok` audit entry and shown on the account page. Every lifetime ends immediately on sign-out, password change (new session epoch) or device-certificate revocation; a session bound to a certificate is refused from any connection that does not present it.

## Privilege model
- The hub's own login is the administrator boundary (see top). One admin identity by design until the identity layer lands (roadmap).
- **Container control has no Docker socket in any container.** The hub writes exactly one `ops/requests/request.json`; `aegis-watchdog` (a root systemd service on the host, `ops/aegis-watchdog.py`) validates it against an allow-list, refuses `stop` for caddy/hub, orders dependents (caddy→hub, litellm-db→litellm, ollama→litellm, prometheus→grafana), executes with the docker CLI, writes `ops/responses/<ts>-<id>.json`, archives the request, and publishes `status.json` every 5 s. Only one request can be pending.
- The hub shares Caddy's network namespace: it can reach the Caddy admin API, LiteLLM (with the master
  key), Ollama (read + delete) and `modeld` (pulls). No other container can reach any of those admin surfaces.
- The hub's filesystem is read-only except: `proxy/policy/` (policy JSON), `caddy/sites-enabled/`
  (hostname site file), `caddy/hub/state/` (webhook, hostname), `proxy/audit/` (append-only logs).
- The isolation layer — `caddy/conf/Caddyfile`, `docker-compose.yml`, networks, mounts, capabilities — is
  mounted read-only into the hub and is **console-only** to change.
- Every POST requires a CSRF token bound to the hub process; every state change writes to
  `proxy/audit/hub-audit.jsonl` and, if configured, the alert webhook.

## Policy semantics (Safety → VetoGuard policy)
Categories are Llama Guard 3 hazard codes — definitions in the model card: <https://github.com/meta-llama/PurpleLlama/blob/main/Llama-Guard3/8B/MODEL_CARD.md>.
- **locked:** S4 — always blocked, always immutable, always sealed as evidence; no UI to change it.
- **illegal (blocked by default):** S1, S2, S3, S9.
- **protected (blocked by default):** S10, S11.
- **adult/legal (allowed by default):** S5, S6, S7, S8, S12, S13, S14.

**Classifier is mandatory and fail-closed:** if the chosen model is not installed, not loadable or unreachable, every request is refused (503 `guard_unavailable`). If VRAM pressure evicts it, Ollama reloads it on the next request (~20 s once). Load the main model *before* choosing a larger classifier so both fit. The dropdown lists installed models named *guard*, *shield* or *guardian*. Each family needs a **verdict adapter** (how it is asked, how its answer is read); today only Llama Guard has one, so other families are listed but not selectable. If a classifier ever returns an answer the adapter cannot read, the request is **refused** (503 `guard_verdict_unparseable`) and the audit entry records `got='<first 120 chars of the classifier's answer>' expected='…'` — classifier output only, never user content — and the event is alerted.

The lexical tripwire (sentinel, CSAM terms, malware intent, plus admin-added regexes) runs before
the classifier. The classifier runs on input and on output (streaming is buffered and released only
after classification). If the guard model is unreachable the request is refused — this is not configurable.

## Retention and sealed evidence
- Every veto entry is flagged **immutable** when its category is in the immutable set (default S4, S3, S10, S11 — S4 always) or it came from a CSAM tripwire. See `docs/EVIDENCE.md` for the evidence path. **Clear log** removes only non-immutable entries; immutable ones expire after `immutable_days` (minimum 90, default 730). Clearing is itself audited with counts.
- Vetoes in the **evidence** set (default S4 + CSAM tripwires; S4 always) also produce a sealed record in `proxy/evidence/`: full request (and output), timestamp, key alias, client IP and user agent, model, categories with names, and the exact matched spans for tripwire hits. Records are Fernet-encrypted with `VETO_EVIDENCE_KEY` and hash-chained (`prev_hash → hash`), so removal or alteration is detectable. A plaintext `index.jsonl` holds metadata only. The hub lists ids and hashes; it never decrypts. Records expire after `evidence.days` (minimum 90, default 730), audited.
- **Handoff from the hub:** Safety → Audit log → "Export for handoff" re-encrypts one record with a fresh key, offers the `.aegis-evidence` file for download and shows the key once — send file and key by separate channels; the recipient opens it with `scripts/evidence-open.py` (standalone, needs only `cryptography`). Export and download are audited and alerted.
- **Bulk export (console):** `scripts/evidence-export.sh <id|all> <outdir>` decrypts inside the LiteLLM container, verifies the whole chain, writes plaintext JSON + `CHAIN-VERIFICATION.txt` + `SHA256SUMS` into a 0700 directory. Keep an offline copy of `VETO_EVIDENCE_KEY`; without it records are unreadable.

**What is sealed today: text only** — request messages/prompt, text output for output-side vetoes, timestamp, key alias, client IP/agent, model, categories, matched spans, chain links. For image generation (roadmap): flagged images are destroyed, never stored; evidence is prompt + metadata + verdict + a perceptual hash. See `docs/designs/portal-and-identity.md`.

## Guard model choice (measured 2026-09-24 on 2× Tesla T4, Mixtral 8x7B resident)
| Guard | Placement | 6000-char classification | Mixtral gen | Notes |
|---|---|---|---|---|
| llama-guard3:1b | mostly CPU (0.1 GiB VRAM) | **0.12 s** warm | 12.5 tok/s | current setting |
| llama-guard3:8b + Mixtral (observed 15:02–15:12) | thrash → CPU fallback | — | — | do not combine |
| **llama-guard3:8b + gemma3:27b (current, 17:15)** | both 100% GPU, 27 of 30 GB | 0.07 s warm; **2.9 s for a full request incl. pre + post classification** | 15.5 tok/s | load Gemma first, then the guard |
| llama-guard3:8b | GPU | 0.07 s warm | 8.6 tok/s | **evicts Mixtral** — 10 s + 26 s reload per request; unusable on this VRAM |
| llama-guard3:8b | CPU only | 14–21 s | 12.5 tok/s | unusable latency |

**Pairing 8B safely (done 2026-09-24):** `gemma3:27b` (18 GB) as the main model, loaded before the guard; policy set to 8B. Keys must list `gemma3` (Access → API keys → Update models). 8B is the better classifier (Meta reports the 1B distillation loses recall on paraphrased and
multilingual content). It becomes viable when either the main model is ≤ ~20 GB or the guard moves
to the Intel Arc cards. Both are one setting away in this page once the hardware allows.
