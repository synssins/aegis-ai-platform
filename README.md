# Aegis AI Platform

A universally deployable, cryptographically siloed AI inference platform running on an Ubuntu guest within a Proxmox hypervisor.

## Hardware & Architecture
* **Compute:** 2x NVIDIA Tesla T4 (Text Inference) & 2x Intel Arc Pro B60 (Visuals).
* **Virtualization:** Proxmox bare-metal host with PCI-E VFIO passthrough and automated 32GB ReBAR resizing.
* **Networking:** Completely isolated Docker bridge (`ai-secure-net`) hidden behind a Caddy reverse proxy handling internal TLS.

## Absolute Security Guardrails
* **The Veto Proxy:** A custom LiteLLM pre-call interceptor (`veto_filter.py`) utilizing zero-tolerance regex strict-matching. It instantly severs any inference requests attempting to generate malware, reverse shells, or illegal explicit material before they ever reach the routing logic.
* **Air-gapped Ports:** No backend container binds to host ports. All ingress is strictly funneled through encrypted HTTPS gateways.

## Inference Stack
* **Engine:** Ollama managing hot-swappable GGUF models, dynamic VRAM allocation, and system RAM offloading for massive context windows (131k+).
* **Gateway:** LiteLLM handling OpenAI-compliant translation and unified API routing.
* **Interface:** OpenWebUI providing a centralized frontend for chat, document vectorization, and localized token-per-second benchmarking.
