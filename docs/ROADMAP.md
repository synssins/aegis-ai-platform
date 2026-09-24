# Roadmap

Ordered by dependency, not by desire. Each item names its safety precondition.

| # | Item | Precondition |
|---|---|---|
| 1 | Host hardening (scoped sudo, SSH key-only, firewall auto-update; **NVIDIA CDI done 2026-09-24**) | Supervised session; console access verified from a second device |
| 2 | Public hostname + Let's Encrypt via `/hub` | **Done (framework):** Cloudflare DNS-01 build shipped; operator applies hostname + token in Gateway → Public hostname |
| 3 | Monitoring (Prometheus, node-exporter, DCGM exporter, Grafana at `/grafana`) | **Done (profile `monitoring`)**; set `GRAFANA_ENABLED=1` to surface it in the hub |
| 4 | Llama Guard 8B on the Intel Arc cards — **done 2026-09-24 (`ollama-intel` pool holds the classifier); runtime proven:** stock Ollama image, Vulkan backend, 45 tok/s on one B60 (design: `docs/designs/gpu-runtime-and-scheduling.md`) | Phase 1 of the design: add the `ollama-intel` pool, pin the guard to it, sentinel phase 3 green |
| 4b | GPU pools (by vendor or per card), request-driven load/unload with priorities, "first card available" placement, then farm role split (head + workers) | Design above; phases 2–4 each gated by suite assertions; cross-app eviction waits for items 7/8 |
| 5 | Content-filter expansion beyond the minimum (category policy, per-key policies, review UI for the audit log) | Audit-log review process defined |
| 6 | Tool calling / MCP servers | `tools` network; tool results scanned (already in VetoGuard); per-tool egress allow-list; no tool may reach `backend` |
| 7 | Fish Speech (TTS) under the hub | GPU assignment; output stays text→audio only |
| 8 | ComfyUI (image generation) | **Hard gate:** prompt classifier + output multimodal classifier + isolated audit log, tested with sentinels before any model is loaded |
| 9 | **Portal + single identity** — **shipped 2026-09-24:** portal at `/`, hub accounts with grants, portal-native gated chat; remaining: Images/Gallery/Speech sections, Open WebUI SSO — landing page at `/` with Chat · Images · Speech · Gallery · Monitoring tiles by group; one login for everything (Authelia IdP behind Caddy `forward_auth`; Open WebUI via OIDC; Grafana via auth-proxy roles; hub trusts the `admins` group); per-user gallery with admin-published globals; per-user feature grants (e.g. `grafana-viewers`); **public status tile = `/status` (shipped)** | Supervised (changes how you log in); design doc first, Gemini review, then phased: IdP → portal → app SSO → gallery |
| 10 | Hub key management UI — **done** (mint / revoke / update models) |
| 11 | Verdict adapters for other safety families (ShieldGemma, WildGuard, Granite Guardian) in `proxy/veto_filter.py` `ADAPTERS` — request template + answer parser per family, mapped onto the S-category policy; optional two-classifier mode | Framework shipped 2026-09-24 (Llama Guard adapter); each new adapter benchmarked against the sentinel suite before it is selectable |
 **Done** — by operator decision the hub holds the master key; mitigations: edge basic-auth, Caddy-namespace-only reachability, read-only fs, CSRF, audit + alert on every action |
