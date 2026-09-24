# Roadmap

Ordered by dependency, not by desire. Each item names its safety precondition.

| # | Item | Precondition |
|---|---|---|
| 1 | Host hardening (scoped sudo, SSH key-only, firewall auto-update) | Supervised session; console access verified from a second device |
| 2 | Public hostname + Let's Encrypt via `/hub` | DNS record; HTTP-01 needs 80/443 forwarded **or** DNS-01 with a provider-module Caddy build |
| 3 | Monitoring (Prometheus, node-exporter, DCGM exporter, Grafana at `/grafana`) | Read-only exporters; Grafana behind its own auth |
| 4 | Move Llama Guard to a dedicated GPU (Intel Arc via SYCL/IPEX build) and upgrade to 8B | Driver + runtime validated on a scratch model first |
| 5 | Content-filter expansion beyond the minimum (category policy, per-key policies, review UI for the audit log) | Audit-log review process defined |
| 6 | Tool calling / MCP servers | `tools` network; tool results scanned (already in VetoGuard); per-tool egress allow-list; no tool may reach `backend` |
| 7 | Fish Speech (TTS) under the hub | GPU assignment; output stays text→audio only |
| 8 | ComfyUI (image generation) | **Hard gate:** prompt classifier + output multimodal classifier + isolated audit log, tested with sentinels before any model is loaded |
| 9 | Hub key management UI | Design review: the hub must not hold the master key |
