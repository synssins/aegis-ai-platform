# Applying the hardened stack (rev 2)

Every step is independently revertible; data directories are never touched.
`$LAN_IP` below is the value of `AEGIS_LAN_IP` in `.env`.

0. **Snapshot the VM** (hypervisor) if you can. Otherwise the config backup in step 1 is the rollback.
1. Baseline + backup: `git init` (if new), `scripts/install-hooks.sh`, commit the current tree; also `cp -a` the current config files to `backup/<date>/`.
2. `cp .env.example .env && chmod 600 .env` — fill with `openssl rand -hex 32` values; set `AEGIS_LAN_IP`, `ACME_EMAIL`; hash the hub password. Leave `OPENWEBUI_UPSTREAM_KEY` blank.
3. Permissions: `sudo chown root:root caddy/Caddyfile && sudo chmod 600 caddy/Caddyfile`; `chmod 700 openwebui caddy/data proxy/audit proxy/db`.
4. Pull the guard model **before** the network split removes Ollama's egress: `docker exec ollama ollama pull llama-guard3:1b` (or `scripts/pull-model.sh llama-guard3:1b` afterwards).
5. `docker compose down`
6. Copy `proposed/` files into place (compose, Caddyfile, sites-available, hub, proxy/*, scripts/*).
7. `docker compose up -d` — wait for `litellm-db` healthy and LiteLLM's Prisma migration (`docker logs -f litellm`).
8. Mint OpenWebUI's key: `scripts/mint-key.sh mint openwebui mixtral 120 400000` → put it in `.env` as `OPENWEBUI_UPSTREAM_KEY` → `docker compose up -d openwebui`.
9. Mint a test key: `scripts/mint-key.sh mint sentinel-tests mixtral 60 100000` → `.env` `TEST_API_KEY`.
10. `scripts/sentinel_test.py --label post-migration` — must be all-pass. Report lands in `docs/tests/`.
11. Build the gateway image once: `docker build -t aegis/caddy:2.11.4-cloudflare caddy/build`.
12. Seed the policy: the hub writes `proxy/policy/veto-policy.json` on first start (defaults: S1–S4, S9–S11 blocked). `sudo chmod 700 proxy/policy caddy/hub/state`.
13. Optional profiles: `docker compose --profile monitoring up -d` (set `GRAFANA_ADMIN_PASSWORD`, `GRAFANA_ENABLED=1`); `--profile apps` only after GPU assignment.
14. Log the change in `docs/CHANGELOG.md` (key aliases only, never keys); commit.

Rollback: `docker compose down && cp -a backup/<date>/* . && docker compose up -d`.

**Host-level steps — supervised only:** scoped sudoers, SSH key-only auth, firewall auto-update policy.
