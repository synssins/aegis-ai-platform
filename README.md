# Aegis AI Platform

A universally deployable, cryptographically siloed AI inference platform designed for bare-metal hypervisors. 

## Architecture
* **Compute:** Hardware-agnostic GPU passthrough (PCIe VFIO) with automated ReBAR support (specifically for Intel GPUs installed on hardware that does not support ReBAR, such as the Dell PowerEdge R740).
* **Virtualization:** Proxmox bare-metal host running an isolated Linux guest.
* **Networking:** Completely isolated Docker bridge (`ai-secure-net`) hidden behind a Caddy reverse proxy handling internal TLS. No internal container ports are bound to the host.

## Security Guardrails
* **The Veto Proxy:** A custom LiteLLM pre-call interceptor (`veto_filter.py`) utilizing zero-tolerance regex strict-matching. It instantly severs any inference requests attempting to generate malware, reverse shells, or illegal explicit material before they reach the routing logic.
* **Air-gapped Ports:** All internal ingress is strictly funneled through encrypted HTTPS gateways. 

## Inference Stack
* **Engine:** Ollama managing hot-swappable GGUF models, dynamic VRAM allocation, and system RAM offloading for massive context windows.
* **Gateway:** LiteLLM handling OpenAI-compliant translation and unified API routing.
* **Interface:** OpenWebUI providing a centralized frontend for chat, document vectorization, and localized token-per-second benchmarking.
