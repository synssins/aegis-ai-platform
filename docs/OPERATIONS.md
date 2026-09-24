# Operations

## Daily
- `https://<LAN_IP>/status` — load, resident models, service health (public, no login).
- Hub → Overview → Dashboard: safety posture, certificates, recent vetoes; **a red "GPU residency lost" banner
  means inference has fallen back to CPU** — restart `ollama` from Services.

## Container control (no Docker socket in any container)
Hub → Overview → Services: tick containers, Start / Stop / Restart. Requests go to `aegis-watchdog`, a root
systemd service on the host that reads one request file, enforces an allow-list and dependency order
(caddy→hub, litellm-db→litellm, ollama→litellm, prometheus→grafana), and writes a response with a per-step log.
`caddy` and `hub` can only be restarted. One request at a time. Console equivalents: `docker compose …`.
Watchdog logs: `journalctl -u aegis-watchdog`.

## Models
- Pull from the hub (Models → Pull) or `scripts/pull-model.sh <name>` — both use a throw-away puller; the
  inference engine never has internet access.
- Load order matters for VRAM: load the main model, then choose the classifier in Safety → VetoGuard policy.
- Expose a model to apps from Models → Installed; tool-capable models (Ollama `tools` capability) are registered on
  the native chat API so assistants such as Home Assistant get real tool calls.
- Keys: Access → API keys (mint / update models / revoke). Console: `scripts/mint-key.sh`.

## GPUs
GPUs are injected with CDI (`/etc/cdi/nvidia.yaml`). This is deliberate: the legacy NVIDIA runtime hook loses
device access on a host `systemctl daemon-reload` (symptom: `Failed to initialize NVML: Unknown Error`, models
resident with 0 VRAM). After a driver upgrade run `sudo nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml`
and restart `ollama` and `dcgm-exporter`.

## Disk
Model store `llm/gguf/` dominates. Watch `/status`. To grow an LVM root online:
`sudo lvextend -L +<size> -r /dev/<vg>/<lv>`. Reclaim: `docker image prune`, remove models from the hub,
delete `llm/gguf/models/blobs/*partial*` after a failed pull.

## Certificates
LAN address: Caddy's internal CA (install `caddy/data/caddy/pki/authorities/local/root.crt` on clients to
remove warnings). Public hostname: Let's Encrypt via Cloudflare DNS-01 from Gateway → Public hostname; renews
automatically; status in Gateway → Certificates.

## Backups
Back up: `.env` (secrets — offline copy), `proxy/db/` (LiteLLM keys and hub-exposed models), `openwebui/`
(users, chats), `caddy/data/` (CA, certificates), `caddy/hub/state/` (admin account, hostname, webhook),
`proxy/policy/`, `proxy/audit/`, `proxy/evidence/`. Models are re-downloadable. Restore = put the directories
back with root ownership and `docker compose up -d`.

## Upgrades
See `docs/INSTALL.md` → Upgrading. Every image is pinned; read the changelog before bumping a pin.

## Recovery
- Lost hub password/authenticator: `scripts/hub-reset-admin.sh` removes the accounts; the first-run wizard
  reappears at `/hub`.
- Hub unreachable: `docker compose restart caddy hub` on the console.
- Watchdog stuck: `sudo systemctl restart aegis-watchdog`; a stale `ops/requests/request.json` can be moved to `ops/archive/`.

## Alerts
Hub → Safety → Alerts: a webhook receives every administrative action and every illegal/protected-class veto
(codes, names, key alias, device fingerprint, time — never content).
