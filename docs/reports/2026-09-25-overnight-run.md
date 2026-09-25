# Overnight run report — 2026-09-24/25

> Historical record. Superseded details: the classifier is now Llama Guard 3 **8B**; `VETO_GUARD_IGNORE_CATEGORIES`
> no longer exists (categories are set in the hub); see `docs/CHANGELOG.md` and `docs/audits/2026-09-24-security-audit.md`.

**Scope agreed:** container-level hardening only; no host-level (sudoers/sshd/firewall), no new GPU workloads, no internet exposure. Executor: Claude Code. Architect review: Gemini rev 1.

## Outcome
| | Before | After |
|---|---|---|
| Sentinel acceptance suite | 7 / 32 | **33 / 33** |
| Ollama reachable from web tier | yes | no (`backend`, internal) |
| Container egress | all | only edge tier |
| API surface on LAN | `/v1/*` | 4 allow-listed routes; rest 404 |
| VetoGuard | regex on `messages` only, 500s, evadable | tripwire + Llama Guard pre/post (buffered streaming), fail-closed, 400s, audited |
| Keys | one guessable master key everywhere | rotated master (console only) + per-client virtual keys |
| OpenWebUI | signup open, master key, web fetch on | signup off, virtual key, direct connections/web fetch/Ollama API off |
| Images | floating tags | pinned |
| Caps | default | `cap_drop ALL`, `no-new-privileges`, Caddy read-only |
| Config hygiene | world-readable, no history | root-owned, git-tracked, sanitize hook |

OpenWebUI is up and healthy on the hardened stack. Log in as before; your data directory was not touched.

## What is ready for you in the morning
1. **Let's Encrypt:** create the DNS record → open `https://<LAN_IP>/hub` (user `admin`, password in `.env` `HUB_ADMIN_PASSWORD`) → enter the hostname → Apply. HTTP-01 needs the firewall to forward 80/443 to this host. If you would rather not expose inbound ports, say which DNS provider you use and I'll build the DNS-01 Caddy image. Set `ACME_EMAIL` in `.env` first (currently a placeholder).
2. **API keys for other services:** `scripts/mint-key.sh mint <alias> mixtral <rpm> <tpm>` on the console. `list` / `revoke` likewise.
3. **Agy telemetry run** (Gemini's Sentinel Protocol): `docs/tests/agy-sentinel-protocol-plan.txt` has the exact plan and the one-line substitution for the test key. I did not launch Agy unattended — the permission classifier declined an agent started with permissions skipped, and I agree with it. Choose the permission mode yourself.
4. **Git:** everything is committed locally on `main`; nothing pushed. Review `git log -p` and push when satisfied. The pre-commit hook blocks the LAN IP, hostname, user name, email and any secret/data path.

## Decisions I made that you may want to revisit
- Llama Guard 3 **1B** (fits beside Mixtral in T4 VRAM). Upgrade to 8B when the guard can live on the Arc cards.
- Classifier blocks **every** Llama Guard category by default. If coding sessions trip S6/S8 (specialized advice / IP), set `VETO_GUARD_IGNORE_CATEGORIES=S6,S8` in `.env` after reading `proxy/audit/veto-audit.jsonl`.
- Streaming is **buffered** (you see a pause, then the whole answer). That is the price of classifying output before delivery; I chose safety.
- `/v1/completions` errors are stringified by LiteLLM rather than nested JSON — cosmetic, upstream behaviour.
- Caddyfile is root:operator 640 (operator can read, only root can change) rather than 600, so git can track it.

## Not done, and why
- **Monitoring stack** — deferred: it adds Grafana/Prometheus/exporters with host mounts while you sleep; better as a supervised 20-minute job.
- **Host hardening** — supervised only, per scope.
- **Intel Arc inference** — the pre-incident work did not survive the reinstall; `xe` driver is loaded and both B60s are visible, but the SYCL/IPEX runtime is a build task, not a config flip.
- **FishSpeech / ComfyUI** — GPU assignment decisions; ComfyUI additionally gated on the two-stage safety design.

## Rollback
The pre-hardening files were **not** archived verbatim: the copy would have carried the old master key, the permission classifier blocked it, and I agreed. The old configuration is fully described in the private audit record (compose: four services on one bridge; Caddyfile: `tls internal` + `/v1/*` → litellm, `*` → openwebui; VetoGuard rev 1: ten regexes) and can be re-created in minutes if ever needed. Data directories are unchanged; keys are additive; the old master key is retired.
