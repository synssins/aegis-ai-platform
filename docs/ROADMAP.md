# Roadmap

Ordered by dependency, not by desire. Each item names its safety precondition.

| # | Item | Precondition |
|---|---|---|
| 1 | Host hardening (scoped sudo, SSH key-only, firewall auto-update, NVIDIA runtime CDI mode so containers cannot silently lose GPUs) | Supervised session; console access verified from a second device |
| 2 | Public hostname + Let's Encrypt via `/hub` | **Done (framework):** Cloudflare DNS-01 build shipped; operator applies hostname + token in Gateway → Public hostname |
| 3 | Monitoring (Prometheus, node-exporter, DCGM exporter, Grafana at `/grafana`) | **Done (profile `monitoring`)**; set `GRAFANA_ENABLED=1` to surface it in the hub |
| 4 | Llama Guard 8B — needs a ≤ 20 GB main model **or** the guard on the Intel Arc cards (SYCL/IPEX runtime) | Measured: 8B cannot co-reside with Mixtral on 2× T4 (see docs/HUB.md) |
| 5 | Content-filter expansion beyond the minimum (category policy, per-key policies, review UI for the audit log) | Audit-log review process defined |
| 6 | Tool calling / MCP servers | `tools` network; tool results scanned (already in VetoGuard); per-tool egress allow-list; no tool may reach `backend` |
| 7 | Fish Speech (TTS) under the hub | GPU assignment; output stays text→audio only |
| 8 | ComfyUI (image generation) | **Hard gate:** prompt classifier + output multimodal classifier + isolated audit log, tested with sentinels before any model is loaded |
| 9 | Hub key management UI | **Done** — by operator decision the hub holds the master key; mitigations: edge basic-auth, Caddy-namespace-only reachability, read-only fs, CSRF, audit + alert on every action |
