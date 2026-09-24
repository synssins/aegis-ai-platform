# Aegis AI Platform

A self-hosted LLM inference stack — Caddy → Open WebUI / OpenAI-compatible API → LiteLLM → Ollama — built on the
assumption that the hosting environment is never truly secure, and that content safety is
mandatory rather than optional.

**What makes it different**
- **Two-network topology.** The inference engine lives on an `internal: true` network with no egress and no
  LAN reachability. Only the reverse proxy publishes ports. No container holds the Docker socket — a host
  watchdog performs restarts from a one-file request queue.
- **VetoGuard.** Every request and every response (streamed output included) passes a lexical tripwire and a
  Llama Guard 3 classifier, fail-closed. Vetoes are audited without content; the serious class produces sealed,
  hash-chained, encrypted evidence with a law-enforcement handoff path.
- **Admin hub.** Own login (argon2id + mandatory TOTP), one place to choose the classifier, policy, retention,
  models, API keys, certificates (Let's Encrypt via DNS-01, no inbound ports), container control, metrics.
  The isolation layer is view-only there and console-only to change.
- **Public status page**, hardened containers (all capabilities dropped, pinned upstream images, no forks),
  GPUs via CDI so they survive host reloads.
- **Reproducible and auditable.** Ordered install, an acceptance suite whose reports are committed, a
  pre-commit hook that refuses to leak anything machine-specific, and a changelog for every significant change.

## Documentation
| | |
|---|---|
| [docs/INSTALL.md](docs/INSTALL.md) | fresh install, upgrade, rollback |
| [docs/CONFIG.md](docs/CONFIG.md) | `.env` reference; what is hub-managed vs console-only |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | networks, services, privilege boundaries |
| [docs/SAFETY.md](docs/SAFETY.md) | how VetoGuard works, categories (Llama Guard S1–S14), policy, responses |
| [docs/EVIDENCE.md](docs/EVIDENCE.md) | sealed evidence: what is captured, how it is protected, how law enforcement opens it |
| [docs/HUB.md](docs/HUB.md) | the admin hub, page by page |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | daily operation, container control, GPUs, disk, backups, recovery |
| [docs/TESTING.md](docs/TESTING.md) | acceptance suite and adversarial reviews |
| [docs/SECURITY.md](docs/SECURITY.md) | threat model and known limits |
| [docs/HARDWARE-REBAR.md](docs/HARDWARE-REBAR.md) | Resizable BAR for GPUs that need it — bare metal, hypervisor + VM, firmware without ReBAR |
| [docs/ROADMAP.md](docs/ROADMAP.md) · [docs/designs/](docs/designs/) | what is next and the designs under review |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | every significant change, with verification |

The same pages are published to the repository wiki with `scripts/publish-wiki.sh`.

## Layout
```
docker-compose.yml        the stack (edge / backend / mgmt / monitoring / apps networks, profiles)
caddy/conf/Caddyfile      gateway — root-owned, read-only in containers, console-only to change
caddy/hub/hub.py          admin hub (Python stdlib + argon2, cryptography, qrcode)
proxy/veto_filter.py      VetoGuard (tripwire + classifier adapters + policy + audit + evidence)
proxy/config.yaml         LiteLLM models + settings
ops/aegis-watchdog.*      host-side container controller (systemd)
monitoring/               Prometheus + Grafana provisioning
scripts/                  install-hooks, sanitize-check, pull-model, mint-key, sentinel_test, evidence-*, hub-reset-admin, publish-wiki
docs/                     documentation, test reports, adversarial review records, designs
.env.example              every secret and site-specific value
```

## Requirements
Docker ≥ 28 + Compose, NVIDIA container toolkit with CDI, ~32 GB VRAM for the reference pairing
(Gemma 3 27B + Llama Guard 3 8B). See `docs/INSTALL.md`.

## Status
Running in production for its author. Contributions welcome — read `docs/SECURITY.md` and `docs/SAFETY.md`
first; changes that weaken the safety pipeline will not be merged.

## License
MIT — see `LICENSE`.
