# Aegis Hub — admin control centre

`https://<LAN_IP>/hub` · user `admin`. **Own login, not basic-auth:** argon2id password hashes (64 MiB, t=3), mandatory TOTP (RFC 6238; secret Fernet-encrypted at rest with `HUB_SECRET_KEY`), HMAC-signed HttpOnly/Secure/SameSite=Strict session cookies (12 h), lockout (5 failures/user → 5 min; 20/IP → 15 min), every login/failure audited. No password is ever stored or printed anywhere: on first run (no administrator yet) `/hub` shows a **setup wizard** — choose the admin username, set a policy-checked password, enrol MFA — all in the browser. Recovery is console-only: `scripts/hub-reset-admin.sh` removes the administrator so the wizard runs again.
Dark theme. Fixed left navigation with collapsible categories (the active one open), one level of sub-pages; the right pane scrolls independently. Every table paginates (10/25/50/100 per page, prev/next) via URL query parameters.

| Category | Page | Can change | Notes |
|---|---|---|---|
| Overview | Dashboard | — | services by network, safety posture, VRAM residency, certificates, recent vetoes |
| | Services | start / stop / restart (checked containers) | real container status from the host **watchdog**; caddy and hub can only be restarted; one request at a time; every watchdog response (log + errors) listed |
| Safety | VetoGuard policy | **classifier model (the one place it is chosen — saving loads it and unloads other guards)**, blocked categories, tripwires, extra regexes, diagnostics snippet toggle (default off) | **S4 is locked on**; classifier and fail-closed cannot be disabled; every save is audited + alerted |
| | Audit log | — | last 150 vetoes and 100 admin actions; never contains content |
| | Alerts | webhook URL | Discord/Slack/generic JSON; "Send test" |
| Models | Installed | expose / load / unload / remove; "Set as classifier" for guard-family models | expose = register in LiteLLM under a public name (through VetoGuard) — on the native chat API with real tool calls when the model advertises `tools`, text-only otherwise (capability tags shown); guard models never exposable and not loaded/unloaded by hand — their residency follows the policy choice; the active classifier cannot be removed |
| | Pull | pull | via `modeld` — the only container with both internet and the model store. Apps never fetch their own |
| | Exposed to apps | unexpose (hub-created only) | models from `config.yaml` are console-managed |
| Access | API keys | mint / revoke | per-client, model-scoped, rate-limited; key shown once |
| | Admin account | change password; re-enrol MFA | argon2id; policy ≥ 14 chars / 3 of 4 classes; changing the password signs out other sessions |
| Gateway | Certificates | — | live TLS probe of every served host |
| | Public hostname | hostname + Cloudflare token | writes exactly one templated site file; Let's Encrypt via DNS-01, no inbound ports |
| | Isolation | — | **read-only** view of the Caddyfile and compose network wiring |

## Privilege model
- The hub's own login is the administrator boundary (see top). One admin identity by design until the identity layer lands (roadmap).
- **Container control has no Docker socket in any container.** The hub writes exactly one `ops/requests/request.json`; `aegis-watchdog` (a root systemd service on the host, `ops/aegis-watchdog.py`) validates it against an allow-list, refuses `stop` for caddy/hub, orders dependents (caddy→hub, litellm-db→litellm, ollama→litellm, prometheus→grafana), executes with the docker CLI, writes `ops/responses/<ts>-<id>.json`, archives the request, and publishes `status.json` every 5 s. Only one request can be pending.
- The hub shares Caddy's network namespace: it can reach the Caddy admin API, LiteLLM (with the master
  key), Ollama (read + delete) and `modeld` (pulls). No other container can reach any of those admin surfaces.
- The hub's filesystem is read-only except: `proxy/policy/` (policy JSON), `caddy/sites-enabled/`
  (hostname site file), `caddy/hub/state/` (webhook, hostname), `proxy/audit/` (append-only logs).
- The isolation layer — `caddy/Caddyfile`, `docker-compose.yml`, networks, mounts, capabilities — is
  mounted read-only into the hub and is **console-only** to change.
- Every POST requires a CSRF token bound to the hub process; every state change writes to
  `proxy/audit/hub-audit.jsonl` and, if configured, the alert webhook.

## Policy semantics (Safety → VetoGuard policy)
Llama Guard 3 categories, grouped:
- **locked:** S4 child sexual exploitation — always blocked, no UI to change it.
- **illegal (blocked by default):** S1 violent crimes, S2 non-violent crimes, S3 sex-related crimes, S9 indiscriminate weapons.
- **protected (blocked by default):** S10 hate / protected classes, S11 suicide & self-harm.
- **adult/legal (allowed by default):** S5, S6, S7, S8, S12 sexual content (adult), S13, S14.

**Classifier is mandatory and fail-closed:** if the chosen model is not installed, not loadable or unreachable, every request is refused (503 `guard_unavailable`). If VRAM pressure evicts it, Ollama reloads it on the next request (~20 s once). Load the main model *before* choosing a larger classifier so both fit. The dropdown lists installed models named *guard*, *shield* or *guardian*. Each family needs a **verdict adapter** (how it is asked, how its answer is read); today only Llama Guard has one, so other families are listed but not selectable. If a classifier ever returns an answer the adapter cannot read, the request is **refused** (503 `guard_verdict_unparseable`) and the audit entry records `got='<first 120 chars of the classifier's answer>' expected='…'` — classifier output only, never user content — and the event is alerted.

The lexical tripwire (sentinel, CSAM terms, malware intent, plus admin-added regexes) runs before
the classifier. The classifier runs on input and on output (streaming is buffered and released only
after classification). If the guard model is unreachable the request is refused — this is not configurable.

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
