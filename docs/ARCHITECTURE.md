# Architecture

Aegis is a self-hosted LLM inference platform designed on one assumption: **the network perimeter
can fail silently for months**, so the platform must be defensible on its own.

```
LAN ──► :80/:443 ──► caddy ──┬── /            ──► openwebui ─┐
                    (edge)   ├── /v1/{chat/completions,        │  virtual key
                             │      completions,embeddings,    ▼
                             │      models}   ──► litellm ──► VetoGuard ──► ollama (backend, internal)
                             ├── /hub ──► hub (shares caddy netns; basic-auth)        ▲
                             └── /grafana ──► grafana (optional)                       │
                                                                         llama-guard3 ─┘ (classifier)
```

## Networks
| Network | `internal` | Members | Purpose |
|---|---|---|---|
| `edge` | no | caddy (+hub), openwebui, litellm | Only caddy publishes ports (80/443). Egress allowed. |
| `backend` | **yes** | litellm, ollama, litellm-db | No egress, unreachable from the LAN. Ollama is only addressable by LiteLLM. |
| `tools` (reserved) | yes | future MCP/tool servers | No backend access; per-tool egress policy. |

Model pulls happen in a throw-away container (`scripts/pull-model.sh`) so production Ollama never needs
internet access.

## Services
| Service | Image (pinned) | Runs as | Hardening |
|---|---|---|---|
| caddy | `caddy:2.11.4` | root | `read_only`, `cap_drop ALL` + `NET_BIND_SERVICE`, `no-new-privileges`; admin API on localhost only |
| hub | `python:3.12-alpine` | root (container) | stdlib only; `network_mode: service:caddy`; may write only `sites-enabled/domain.caddy` |
| openwebui | `open-webui:v0.11.4` | root | signup off, direct connections off, web search off, Ollama API off; holds a **virtual** LiteLLM key |
| litellm | `litellm:main-stable` | root | VetoGuard callback; DB-backed virtual keys; admin UI disabled; `/v1/*` beyond the allow-list is 404 at the edge |
| litellm-db | `postgres:16-alpine` | postgres | backend only |
| ollama | `ollama/ollama:0.34.3` | root | backend only; GPU via NVIDIA runtime; `OLLAMA_KEEP_ALIVE=24h` |

All containers drop every capability and set `no-new-privileges`. Because root without
`CAP_DAC_OVERRIDE` obeys ordinary file permissions, container data directories are **root-owned, mode 700**.

## Safety pipeline (VetoGuard, `proxy/veto_filter.py`)
1. **Lexical tripwire** — regex over NFKC-normalised, zero-width-stripped, whitespace-collapsed text, plus
   decoded base64 runs and a despaced pass for unambiguous tokens. Scans the latest user turn, trailing
   tool results, `prompt`, `input`, and multimodal text parts.
2. **Classifier** — Llama Guard 3 via Ollama on the backend network. Pre-call on the request; post-call on
   the output. Streaming responses are buffered and classified before release. **Fail-closed**: if the
   classifier is unavailable, the request is refused (503 `guard_unavailable`).
3. **Audit** — every veto appends a JSON line to `proxy/audit/veto-audit.jsonl` (timestamp, stage,
   reason/category, call id, key alias, model). Never content.

Rejections are HTTP 400 with code `veto_triggered`. A vetoed turn does not poison the conversation.

## Privilege boundaries
- **Gateway config is console-only.** `caddy/Caddyfile` is root-owned (640), mounted read-only everywhere.
- **The hub** can only (re)generate `sites-enabled/domain.caddy` from a fixed template and reload Caddy.
- **API keys** are minted on the console (`scripts/mint-key.sh`), never via the web.
- **Secrets** live in `.env` (600) and are never tracked; `scripts/sanitize-check.sh` blocks commits that
  contain the LAN IP, hostname, user name, email, or any secret/data path.

## Reproducibility
`docs/MIGRATION.md` is the ordered apply procedure. `scripts/sentinel_test.py` is the acceptance suite;
reports land in `docs/tests/`. Every significant change is logged in `docs/CHANGELOG.md`.
