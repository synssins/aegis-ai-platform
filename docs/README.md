# Aegis AI Platform

A self-hosted LLM inference stack — Caddy → Open WebUI / OpenAI-compatible API → LiteLLM → Ollama —
built on the assumption that your network perimeter will eventually fail without telling you.

**What makes it different**
- **Two-network topology.** The inference engine lives on an `internal: true` network with no egress and
  no LAN reachability. Only the reverse proxy publishes ports.
- **VetoGuard.** A LiteLLM hook that combines a normalised lexical tripwire with a Llama Guard 3
  classifier on both input and output — streamed output included — and fails closed. Every veto is
  audited without logging content.
- **Per-client virtual keys** with model allow-lists and rate limits; the master key never leaves the
  console.
- **Console-only gateway config.** The web hub can monitor certificates and set a public hostname for
  Let's Encrypt — and nothing else.
- **Reproducible and auditable.** Pinned images, an ordered migration procedure, an acceptance suite
  whose reports are committed, and a pre-commit hook that refuses to leak anything machine-specific.

## Layout
```
docker-compose.yml        the stack (edge + backend networks)
caddy/Caddyfile           gateway — root-owned, read-only in containers
caddy/hub/hub.py          operator hub (stdlib Python)
proxy/config.yaml         LiteLLM models + settings
proxy/veto_filter.py      VetoGuard (tripwire + classifier + audit)
scripts/                  pull-model, mint-key, sentinel_test, sanitize-check
docs/                     ARCHITECTURE, HUB, SECURITY, ROADMAP, MIGRATION, CHANGELOG, tests/
.env.example              every secret and site-specific value
```

## Quick start
1. `cp .env.example .env && chmod 600 .env` — fill it in (`openssl rand -hex 32` for secrets).
2. Follow `docs/MIGRATION.md` (it doubles as the fresh-install procedure).
3. `scripts/sentinel_test.py --label first-run` — expect all-pass.

## Requirements
Docker + Compose, NVIDIA container runtime (or adapt the `ollama` service), ~32 GB VRAM for the reference
models (Mixtral 8x7B + Llama Guard 3 1B). Everything else is CPU-light.

## Status
Running in production for its author. Contributions welcome — read `docs/SECURITY.md` first; changes that
weaken the safety pipeline will not be merged.

## License
MIT — see `LICENSE`.
