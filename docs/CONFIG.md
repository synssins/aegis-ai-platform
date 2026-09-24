# Configuration reference (`.env`)

`.env` is `chmod 600`, never committed, and is the only place site-specific values and secrets live. Everything
the administrator changes after installation is changed in the hub, not in files — except the isolation layer
(`docker-compose.yml`, `caddy/conf/Caddyfile`), which is console-only by design.

| Variable | Purpose |
|---|---|
| `AEGIS_LAN_IP` | the box's LAN address; site address for the internal-CA certificate; used by the hub for probes |
| `LITELLM_MASTER_KEY` | LiteLLM master key; used only by the hub (admin plane) and console scripts — never by apps |
| `POSTGRES_PASSWORD` | LiteLLM's key/model database |
| `WEBUI_SECRET_KEY` | Open WebUI session signing (unset = sessions reset on every restart) |
| `OPENWEBUI_UPSTREAM_KEY` | a LiteLLM **virtual** key minted for Open WebUI (alias `openwebui`) |
| `OPENWEBUI_DEFAULT_MODEL` | public model name Open WebUI preselects |
| `HUB_SECRET_KEY` | hub session signing and encryption of TOTP secrets at rest (urlsafe base64, 32 bytes) |
| `VETO_EVIDENCE_KEY` | encryption of sealed evidence records — keep an offline copy |
| `VETO_GUARD_IGNORE_CATEGORIES` | legacy; category policy is now set in the hub |
| `ACME_EMAIL` | Let's Encrypt contact for the public hostname |
| `GRAFANA_ADMIN_PASSWORD`, `GRAFANA_ENABLED` | monitoring profile |
| `TEST_API_KEY`, `TEST_MODEL` | acceptance suite key (alias `sentinel-tests`) and model |

Not in `.env` by design: the hub administrator password (argon2id hash in `caddy/hub/state/users.json`),
the Cloudflare API token (root-only site file written by the hub), the public hostname (hub state).

## Set in `docker-compose.yml` (isolation layer, console-only)
| Variable | Service | Purpose |
|---|---|---|
| `VETO_GUARD_URL` | litellm | pool that runs the text classifier (the T4 pool) |
| `GUARD_OLLAMA` | hub | where the hub loads/checks the classifier (same pool) |
| `AEGIS_POOLS` | hub | `name=url,…` GPU pools; `intel` points at the `chatpool` alias so it follows the chat-pool mode |
| `CHATPOOL_NARROW`, `CHATPOOL_WIDE` | hub | the two chat-pool containers behind the alias (mode detection) |
| `AEGIS_INTEL_GPUS` | hub | Intel cards `name:MiB:role` (invisible to DCGM); role `images` or `intel` |
| `COMFY_URL` | hub | the ComfyUI instance behind the gate (`comfyui-intel` by default) |
| `ONEAPI_DEVICE_SELECTOR` | comfyui-intel | which Arc image generation uses |
| `OLLAMA_CONTEXT_LENGTH`, `OLLAMA_KV_CACHE_TYPE`, `OLLAMA_FLASH_ATTENTION` | ollama (T4 pool) | keep both classifiers fully on GPU |

## Hub-managed settings
Safety policy (`proxy/policy/veto-policy.json`), alert webhook and hostname (`caddy/hub/state/hub.json`),
API keys and exposed models (LiteLLM database), device certificates (`caddy/hub/state/devices/`). All written
only by the hub; all changes audited.

## Isolation layer (console only)
`docker-compose.yml`: networks (`edge`, `backend` internal, `mgmt`, `monitoring` internal, `apps` internal),
mounts, capabilities, profiles. `caddy/conf/Caddyfile`: routes, `/v1` allow-list, headers, `/hub`, `/status`,
`/comfy` hard gate. Shown read-only in Hub → Gateway → Isolation.
