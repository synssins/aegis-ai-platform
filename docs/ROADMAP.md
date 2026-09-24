# Roadmap

Ordered by dependency, not by desire. Each item names its safety precondition.

| # | Item | Precondition |
|---|---|---|
| 1 | Host hardening (scoped sudo, SSH key-only, firewall auto-update; **NVIDIA CDI done 2026-09-24**) | Supervised session; console access verified from a second device |
| 2 | Public hostname + Let's Encrypt via `/hub` | **Done (framework):** Cloudflare DNS-01 build shipped; operator applies hostname + token in Gateway → Public hostname |
| 3 | Monitoring (Prometheus, node-exporter, DCGM exporter, Grafana at `/grafana`) | **Done (profile `monitoring`)**; set `GRAFANA_ENABLED=1` to surface it in the hub |
| 4 | Llama Guard 8B — needs a ≤ 20 GB main model **or** the guard on the Intel Arc cards (SYCL/IPEX runtime) | Measured: 8B cannot co-reside with Mixtral on 2× T4 (see docs/HUB.md) |
| 5 | Content-filter expansion beyond the minimum (category policy, per-key policies, review UI for the audit log) | Audit-log review process defined |
| 6 | Tool calling / MCP servers | `tools` network; tool results scanned (already in VetoGuard); per-tool egress allow-list; no tool may reach `backend` |
| 7 | Fish Speech (TTS) under the hub | GPU assignment; output stays text→audio only |
| 8 | ComfyUI (image generation) | **Hard gate:** prompt classifier + output multimodal classifier + isolated audit log, tested with sentinels before any model is loaded |
| 9 | **Portal + single identity** — landing page at `/` with Chat · Images · Speech · Gallery · Monitoring tiles by group; one login for everything (Authelia IdP behind Caddy `forward_auth`; Open WebUI via OIDC; Grafana via auth-proxy roles; hub trusts the `admins` group); per-user gallery with admin-published globals; per-user feature grants (e.g. `grafana-viewers`) | Supervised (changes how you log in); design doc first, Gemini review, then phased: IdP → portal → app SSO → gallery |
| 10 | Hub key management UI — **done** (mint / revoke / update models) |
| 11 | Verdict adapters for other safety families (ShieldGemma, WildGuard, Granite Guardian) in `proxy/veto_filter.py` `ADAPTERS` — request template + answer parser per family, mapped onto the S-category policy; optional two-classifier mode | Framework shipped 2026-09-24 (Llama Guard adapter); each new adapter benchmarked against the sentinel suite before it is selectable |
 **Done** — by operator decision the hub holds the master key; mitigations: edge basic-auth, Caddy-namespace-only reachability, read-only fs, CSRF, audit + alert on every action |
