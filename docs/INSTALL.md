# Installation

Fresh install and upgrade procedure. Every step is independently revertible; data directories are never
touched by later steps. `<LAN_IP>` is the value of `AEGIS_LAN_IP` in `.env`.

## Requirements
- Ubuntu 24.04+ (or any systemd host) with Docker ≥ 28 (CDI enabled) and the Compose plugin.
- NVIDIA driver + `nvidia-container-toolkit` ≥ 1.17 for GPU inference (or adapt the `ollama` service).
- ~32 GB VRAM for the reference pairing (Gemma 3 27B + Llama Guard 3 8B); ~60 GB disk for those models.
- A LAN address for the box. A public hostname is optional (Cloudflare DNS-01; no inbound ports).

## 1. Clone and configure
```
git clone <your fork> /data/ai-unified && cd /data/ai-unified
cp .env.example .env && chmod 600 .env
```
Fill `.env` — every secret with `openssl rand -hex 32`, `AEGIS_LAN_IP`, `ACME_EMAIL`, `HUB_SECRET_KEY`
(urlsafe base64 32 bytes), `VETO_EVIDENCE_KEY` (keep an offline copy). See `docs/CONFIG.md`.

## 2. Host preparation (root)
```
scripts/install-hooks.sh                                  # pre-commit sanitiser
sudo nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml # GPUs via CDI; repeat after driver upgrades
sudo install -m755 ops/aegis-watchdog.py /usr/local/sbin/ && sudo install -m644 ops/aegis-watchdog.service /etc/systemd/system/
sudo install -d -m700 ops/requests ops/responses ops/archive proxy/audit proxy/evidence proxy/policy caddy/hub/state caddy/sites-enabled caddy/config caddy/data
sudo systemctl enable --now aegis-watchdog
sudo chown root:$USER caddy/Caddyfile proxy/config.yaml proxy/veto_filter.py caddy/hub/hub.py && sudo chmod 640 caddy/Caddyfile proxy/config.yaml proxy/veto_filter.py caddy/hub/hub.py
```
Why root-owned 700/640: every container drops all capabilities, so root inside a container obeys ordinary
file permissions; data directories must belong to root, and the gateway config must be writable only by root.

## 2b. Device CA (once)
`docker compose up -d hub && docker exec hub python3 /app/hub.py --init-device-ca` creates the device CA (key encrypted at rest in hub state; public cert at `caddy/sites-enabled/device-ca.pem`, which the Caddyfile references — Caddy will not start without it). Then `docker compose restart caddy hub`.

## 3. Images
`docker build -t aegis/hub:4 caddy/hub/build` — or pull `ghcr.io/<owner>/aegis-hub` once published. All
other images are stock upstream, pinned in `docker-compose.yml`.

## 4. First start
```
docker compose up -d
docker logs -f litellm            # wait for the Prisma migration + "Uvicorn running"
```
Then open `https://<LAN_IP>/hub` — the **first-run wizard** creates the administrator and enrolls MFA in the
browser. Do this promptly: until an administrator exists, anyone on the LAN who reaches `/hub` could claim it.

## 5. Models and keys (from the hub)
- Models → Pull: e.g. `gemma3:27b`, `llama-guard3:8b`. Load the main model **before** choosing a larger classifier.
- Safety → VetoGuard policy: choose the classifier (this loads it). Review blocked categories and retention.
- Models → Installed: Expose the main model under a public name.
- Access → API keys: mint `openwebui` (put it in `.env` as `OPENWEBUI_UPSTREAM_KEY`, then `docker compose up -d openwebui`)
  and one key per other client.

## 6. Verify
`scripts/sentinel_test.py --label first-run --hub-password '<admin password>'` — expect all-pass. Reports land in `docs/tests/`.

## 7. Optional
- Public hostname: Gateway → Public hostname (Cloudflare API token scoped to the zone; DNS record pointing at the LAN IP, proxy off).
- Monitoring: `docker compose --profile monitoring up -d`, set `GRAFANA_ENABLED=1`, `docker compose up -d hub`.
- Apps profile (Fish Speech, ComfyUI): `--profile apps` — ComfyUI stays 503 at the edge until its safety gate exists.

## Upgrading
Pull the repo, read `docs/CHANGELOG.md`, `docker compose config --quiet`, then `docker compose up -d`. Re-run the
sentinel suite. Model store, databases, audit and evidence directories are untouched by upgrades.

## Rollback
`git checkout <previous tag> -- docker-compose.yml caddy/Caddyfile proxy/ caddy/hub/hub.py && docker compose up -d`.
