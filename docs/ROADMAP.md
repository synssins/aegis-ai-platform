# Roadmap

Ordered by dependency, not by desire. Each item names its safety precondition.

| # | Item | Precondition |
|---|---|---|
| 1 | Host hardening (scoped sudo, SSH key-only, firewall auto-update; **NVIDIA CDI done 2026-09-24**) | Supervised session; console access verified from a second device |
| 2 | Public hostname + Let's Encrypt via `/hub` | **Done (framework):** Cloudflare DNS-01 build shipped; operator applies hostname + token in Gateway → Public hostname |
| 3 | Monitoring (Prometheus, node-exporter, DCGM exporter, Grafana at `/grafana`) | **Done (profile `monitoring`)**; set `GRAFANA_ENABLED=1` to surface it in the hub |
| 4 | Llama Guard 8B on the Intel Arc cards — **done 2026-09-24 (`ollama-intel` pool holds the classifier); runtime proven:** stock Ollama image, Vulkan backend, 45 tok/s on one B60 (design: `docs/designs/gpu-runtime-and-scheduling.md`) | Phase 1 of the design: add the `ollama-intel` pool, pin the guard to it, sentinel phase 3 green |
| 4b | GPU pools, request-driven load/unload with priorities — **phase 2 shipped 2026-09-24** (scheduler with admin precedence, pins, holds; wide/normal chat-pool mode with automatic revert; images paused while wide). Remaining: multi-node farm (phase 4), API-key requests under the same policy (needs a LiteLLM hook) | Design `docs/designs/gpu-runtime-and-scheduling.md` |
| 5 | Content-filter expansion beyond the minimum (category policy, per-key policies, review UI for the audit log) | Audit-log review process defined |
| 6 | Tool calling / MCP servers | `tools` network; tool results scanned (already in VetoGuard); per-tool egress allow-list; no tool may reach `backend` |
| 7 | Fish Speech (TTS) under the hub | GPU assignment; output stays text→audio only |
| 8 | ComfyUI (image generation) — **shipped 2026-09-24** behind prompt / file / output gates, gallery with self-purge, admin review switch | Upload gate shipped 2026-09-24; runs on an Arc B60. Remaining: per-user quotas, automatic model unload when VRAM is short (design 4b), mask uploads |
| 9 | **Portal + single identity** — **shipped 2026-09-24:** portal at `/`, hub accounts with grants, portal-native gated chat; remaining: Images/Gallery/Speech sections, Open WebUI SSO — landing page at `/` with Chat · Images · Speech · Gallery · Monitoring tiles by group; one login for everything (Authelia IdP behind Caddy `forward_auth`; Open WebUI via OIDC; Grafana via auth-proxy roles; hub trusts the `admins` group); per-user gallery with admin-published globals; per-user feature grants (e.g. `grafana-viewers`); **public status tile = `/status` (shipped)** | Supervised (changes how you log in); design doc first, Gemini review, then phased: IdP → portal → app SSO → gallery |
| 10 | Hub key management UI — **done** (mint / revoke / update models) |
| 11 | Verdict adapters for other safety families (ShieldGemma, WildGuard, Granite Guardian) in `proxy/veto_filter.py` `ADAPTERS` — request template + answer parser per family, mapped onto the S-category policy; optional two-classifier mode | Framework shipped 2026-09-24 (Llama Guard adapter); each new adapter benchmarked against the sentinel suite before it is selectable |
 **Done** — by operator decision the hub holds the master key; mitigations: edge basic-auth, Caddy-namespace-only reachability, read-only fs, CSRF, audit + alert on every action |

## Next session (plan as of 2026-09-24 late)
**State at shutdown (2026-09-24 ~23:00 UTC):** all work committed and pushed (`main` = origin). Claude can now call `agy`
directly (Claude Code allow-rule; agy trusted workspace `/data/ai-unified` + read-only command allow-list, no
skip-permissions). One smoke review already ran and left **three open findings on `caddy/hub/scheduler.py`**
(`docs/tests/agy-review-round6-01-scheduler.md`) — nothing fixed yet. On power-up: `docker compose --profile apps up -d`
brings the stack (T4 safety pool, Arc #2 chat pool, Arc #1 images); the wide container exists but is stopped;
`qwen3-coder` was the resident chat model, `gemma3` loads on request; classifiers reload from policy on first use.
1. **Adversarial audit round 6** with Gemini (`agy`) over everything shipped since round 5 — brief and scope in
   `docs/audits/2026-09-24-round6-brief.md`. Fix, add suite assertions (new phase 10: portal/scheduler), re-review
   until clean. Record rounds in `docs/tests/agy-review-round6-*.md` like earlier rounds.
2. Then, in order: API-key requests under the scheduler policy (LiteLLM hook), mask uploads, Fish Speech under the
   portal, farm mode (design phase 4).
