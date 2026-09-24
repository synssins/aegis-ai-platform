# Architecture

Aegis is a self-hosted LLM inference platform designed on one assumption: **the network perimeter
can fail silently for months**, so the platform must be defensible on its own.

```
LAN ──► :80/:443 ──► caddy ──┬── /              ──► openwebui ──────────────┐
                             ├── /v1/{chat/completions,completions,          │ virtual key
                             │       embeddings,models} ──► litellm ──► VetoGuard ──► ollama
                             ├── /hub     ──► hub (admin plane, shares caddy netns)   ▲   (backend, internal)
                             ├── /grafana ──► grafana (profile: monitoring)           │
                             ├── /tts     ──► fish-speech (profile: apps)     llama-guard3 (classifier)
                             └── /comfy   ──► 503 HARD GATE until safety gate exists
hub ──► modeld (mgmt, egress) ── pulls into the shared model store ──► ollama sees new models
```

## Networks
| Network | `internal` | Members | Purpose |
|---|---|---|---|
| `edge` | no | caddy(+hub), openwebui, litellm, grafana | Only caddy publishes ports (80/443). Egress allowed. |
| `backend` | **yes** | litellm, ollama, litellm-db, caddy(+hub) | No egress, unreachable from the LAN. Ollama is addressable only by LiteLLM (inference) and the hub (list/delete). |
| `mgmt` | no | caddy(+hub), modeld | `modeld` is a pull-only Ollama with internet access and the model store. Only the hub talks to it. |
| `monitoring` | yes | prometheus, node-exporter, dcgm-exporter, grafana | Grafana is also on `edge` for Caddy. |
| `apps` | yes | fish-speech, comfyui (+edge) | Framework only; profile-gated. |
| `tools` (reserved) | yes | future MCP/tool servers | No backend access; per-tool egress policy. |

## Services
| Service | Image (pinned) | Hardening |
|---|---|---|
| caddy | `aegis/caddy:2.11.4-cloudflare` (local build: caddy 2.11.4 + caddy-dns/cloudflare) | `read_only`, `cap_drop ALL` + `NET_BIND_SERVICE`, admin API localhost-only |
| hub | `python:3.12-alpine`, stdlib only | `network_mode: service:caddy`, read-only fs, writes only policy / site file / state / audit; CSRF on every POST |
| modeld | `ollama/ollama:0.34.3`, no GPU | `mgmt` only; shares `llm/gguf` |
| openwebui | `open-webui:v0.11.4` | signup off, direct connections off, web search off, Ollama API off; holds a **virtual** LiteLLM key |
| litellm | `litellm:main-stable` | VetoGuard callback; DB-backed virtual keys + hub-exposed models; admin UI disabled; policy mounted read-only |
| litellm-db | `postgres:16-alpine` | backend only |
| ollama | `ollama/ollama:0.34.3` | backend only; NVIDIA runtime; `OLLAMA_KEEP_ALIVE=24h` |
| prometheus / node-exporter / dcgm-exporter / grafana | pinned | profile `monitoring`; node-exporter has the stack's one broad (read-only) host mount |
| fish-speech / comfyui | placeholders | profile `apps`; ComfyUI is 503 at the edge regardless |

Every container drops all capabilities and sets `no-new-privileges`. Root without `CAP_DAC_OVERRIDE`
obeys file permissions, so container data directories are **root-owned, mode 700**.

## Safety pipeline (VetoGuard, `proxy/veto_filter.py`)
1. **Lexical tripwire** — regex over NFKC-normalised, zero-width-stripped, whitespace-collapsed text, plus
   decoded base64 runs and a despaced pass for unambiguous tokens. Scans the latest user turn, trailing
   tool results, `prompt`, `input`, multimodal text parts. Admin may add patterns.
2. **Classifier** — Llama Guard 3 via Ollama on the backend network, pre-call and post-call; streaming
   is buffered and released only after classification. **Fail-closed** (503 `guard_unavailable`).
3. **Policy** — `proxy/policy/veto-policy.json`, written only by the hub, hot-reloaded per request.
   Category set and guard model are configurable; S4 is locked; the classifier and fail-closed are not
   configurable. Default: illegal (S1–S4, S9) and protected (S10, S11) blocked; adult/legal allowed.
4. **Audit** — `proxy/audit/veto-audit.jsonl` and `proxy/audit/hub-audit.jsonl`; never content.
   Admin actions also go to an optional webhook.

## Privilege boundaries
- **Isolation layer is console-only:** `caddy/Caddyfile` (root 640, read-only in containers) and
  `docker-compose.yml`. The hub shows both read-only.
- **The hub** may change: VetoGuard policy, models (pull/remove/expose), API keys, public hostname
  (one templated site file with the Cloudflare token), alert webhook. Nothing else.
- **Secrets** live in `.env` (600). `scripts/sanitize-check.sh` blocks commits containing the LAN IP,
  hostname, user name, email, or any secret/data path.

## Reproducibility
`docs/MIGRATION.md` is the ordered install/upgrade procedure. `scripts/sentinel_test.py` is the
acceptance suite (52 assertions); reports are committed in `docs/tests/`. Every significant change is
logged in `docs/CHANGELOG.md`.
