# GPU runtime for Intel Arc, GPU pools, request-driven scheduling, and farm scale

Status: **design for review** (2026-09-24). Nothing here is deployed yet except the measurements. Phase 1 is
small and recommended now; later phases wait for their safety preconditions in `docs/ROADMAP.md`.

## 1. Intel Arc runtime — decision and evidence

### What was measured (this box: 2× Tesla T4 16 GB, 2× Arc Pro B60 24 GB, kernel 7.0 `xe` driver in a VM)

The **stock `ollama/ollama:0.34.3` image already contains the llama.cpp Vulkan backend (`libggml-vulkan.so`)
and Mesa 25.2 with the Intel ANV driver (Battlemage-capable)**. No fork, no rebuild. The Arc cards work with:

```
OLLAMA_VULKAN=1
VK_DRIVER_FILES=/usr/share/vulkan/icd.d/intel_icd.json        # load only the Intel Vulkan driver
devices: /dev/dri/renderD129, /dev/dri/renderD131 (+ card0, card3)  # ONLY the Intel nodes
group_add: [render, video]
```

Result: both cards discovered (`Intel(R) Arc(tm) Pro B60 Graphics`, 23.9 GiB each), `llama-guard3:8b` loaded
33/33 layers on GPU, correct verdicts.

| Engine | Card(s) | Generation | Prompt processing |
|---|---|---|---|
| Ollama/CUDA (current, T4 shared with gemma3:27b) | 1× T4 | 20 tok/s | 350 tok/s |
| Ollama/Vulkan | 1× B60 | **45 tok/s** | 112 tok/s |
| Ollama/Vulkan, layer-split | 2× B60 | 42 tok/s | 83 tok/s |

Model: `llama-guard3:8b` (Q4, 8k context). Splitting one model over two Arcs gives **no** speed-up (layer split
is sequential); it only buys capacity for models that do not fit one card. So Arcs are best used **one model
per card**, which is exactly what the classifier needs.

**Gotcha found and recorded:** passing the whole `/dev/dri` into the container hung Ollama's GPU discovery in
an unkillable (D) state — the Mesa loader enumerates *every* ICD, and in this VM the `virtio-gpu` display
device (venus ICD) blocks. Restricting to the Intel render nodes and the Intel ICD fixes it. The hung
throw-away container (`arc-smoke`) clears on the next reboot; it holds nothing the platform uses.

### Alternatives considered

| Option | Verdict |
|---|---|
| **Ollama + Vulkan (stock image)** | **Chosen.** Zero forks, same model store and admin pipeline as today, hub/LiteLLM/VetoGuard unchanged. Sources: [Ollama GPU docs](https://docs.ollama.com/gpu) (Vulkan on by default), [ollama#13130](https://github.com/ollama/ollama/issues/13130) (Docker device flags). |
| Intel `llm-scaler-vllm` (vLLM XPU) | Keep for the **farm/concurrency** phase: tensor parallel across Arcs, FP8/INT4, continuous batching — 1,495 tok/s aggregate on 4× B60 for GPT-OSS-120B ([vLLM blog](https://vllm.ai/blog/2025-11-11-intel-arc-pro-b), [intel/llm-scaler](https://github.com/intel/llm-scaler), image `intel/llm-scaler-vllm:0.26.0-b2`, 2026-09-08). Costs: a second engine with safetensors models (not GGUF), different admin flow. Not needed for two home users. |
| Intel `llm-scaler-omni` | Relevant later for **Images/Speech on Arc** (ComfyUI + diffusion + TTS on XPU, OpenAI-style `/v1/images/generations`, `/v1/audio/speech`). Candidate for roadmap items 7/8 once their hard gates exist. |
| llama.cpp SYCL / IPEX-LLM | Rejected: IPEX-LLM archived by Intel (Jan 2026); Intel's own guidance is that Vulkan is ~2× SYCL on Arc; both need forks (the operator tried them in the first iteration). |
| Community Ollama-Arc images | Rejected: forks; the stock image now covers it. |

## 2. GPU pools — individual cards or grouped by vendor

One Ollama container = one **pool**. A pool is a set of cards of one vendor; the engine load-balances
inside it. Compose defines the pools; the hub shows them and pins models to them. Two shipped layouts,
selected by compose profile (isolation layer → console-only, as everything in `docker-compose.yml`):

| Profile | Containers | Use |
|---|---|---|
| `pools-vendor` (default) | `ollama` (all NVIDIA, CDI) · `ollama-intel` (all Arc, Vulkan) | simplest; big models can span cards |
| `pools-card` | `ollama-nv0`, `ollama-nv1`, `ollama-arc0`, `ollama-arc1` | one model per card, strict isolation (`CUDA_VISIBLE_DEVICES=n` / `GGML_VK_VISIBLE_DEVICES=n`) |

All pools share the read-only model store (`llm/gguf`); `modeld` stays the only puller. Hub → Models →
**Pools**: capacity, resident models, pin a public model name to a pool or `auto`. The classifier is pinned
by policy (Safety → VetoGuard policy gains a "pool" field) and is the first thing an engine loads.

**Phase 1 plan (recommended now):** add `ollama-intel`, pin `llama-guard3:8b` to it. Effect: the guard
leaves the T4s (frees ~6 GB), gemma3:27b keeps both T4s, and the second Arc is free for a second chat model
or the future image pipeline. VetoGuard's `GUARD_URL` points at the Intel pool; residency check
(`/api/ps`) targets that pool; fail-closed behaviour unchanged.

## 3. Request-driven load/unload and "first card available"

### What already exists
Ollama loads on request, unloads at `keep_alive`, and evicts to make room — **inside one pool**. The gaps
are (a) across pools/vendors and (b) across applications (chat vs image vs video vs speech).

### Broker
`modeld` grows into the **Aegis scheduler** (same hardened image as the hub; no Docker socket; talks only
HTTP to engines on `backend`):

- **Inventory** every 5 s: each pool's `/api/ps` and reported free VRAM (Ollama's own discovery numbers,
  the same for CUDA and Vulkan — no vendor tools needed; DCGM stays for Grafana on NVIDIA).
- **Placement = "first card available":** for a model with pin `auto`, the first pool (admin-ordered)
  whose free VRAM ≥ model size + context reserve gets a pre-warm (`/api/generate` with the model name,
  empty prompt, `keep_alive` from policy). LiteLLM then routes to the pool that has it resident.
- **Routing:** LiteLLM's router lists each public model once per pool (`ollama_chat/<m>` on
  `http://ollama:11434` and `http://ollama-intel:11434`) with `routing_strategy: least-busy` and health
  checks; a pool that lacks the model is simply unhealthy for it until the broker warms it. The hub keeps
  writing this table (it already writes the model list and keys).
- **Unload by request type:** requests carry a type (`chat`, `image`, `video`, `speech`). When a request's
  pool lacks VRAM, the broker evicts by **priority**: never the classifier; then, lowest first: idle video →
  idle image → idle speech → idle chat. Eviction calls: Ollama `keep_alive: 0`; ComfyUI `POST /free
  {"unload_models":true}`; Fish Speech restart via the watchdog. Priorities and idle thresholds live in
  policy (hub → Safety/Models), audited like everything else.
- **Users cannot override** any of this: Open WebUI sees only the public model names LiteLLM exposes; the
  broker and pools are admin-only; `keep_alive`/`num_gpu` in user requests are stripped by VetoGuard's
  pre-call hook (already strips unknown fields on the allow-list).

## 4. Farm scale — same image, more boxes

Single-instance stays the default: one box is a **head** with local pools. A farm adds **workers**:

| Role | Runs | Network |
|---|---|---|
| head (1) | Caddy, hub, portal, LiteLLM + VetoGuard, Postgres, Open WebUI, scheduler, evidence/audit, `modeld` | edge + mesh |
| worker (N) | pools only (`ollama`, `ollama-intel`, later ComfyUI/omni), node-exporter, watchdog | mesh only |

- **Mesh:** WireGuard between head and workers (or the LAN with mTLS if all boxes are on one switch);
  workers expose only the engine ports to the head. No worker is reachable from users.
- **Single interface:** the hub's Pools view lists `<node>/<pool>`; LiteLLM's router lists deployments per
  node/pool; the scheduler's inventory spans nodes. Load balancing = the same `least-busy` router with
  per-node health; failover is automatic.
- **Safety stays one choke point:** every request still passes VetoGuard on the head; the classifier can be
  resident on any pool of any node (pinned per policy, with a fallback pool so a dead node fails closed,
  not open — a request with no reachable classifier is refused, as today).
- **Models:** workers mount the model store read-only from the head (NFS) or sync it (`rsync` from
  `llm/gguf`, triggered by the hub after a pull). Compose on a worker is the same file with `AEGIS_ROLE=worker`
  and `AEGIS_HEAD=<mesh address>`; nothing else differs.
- **Sizing note:** at this point `llm-scaler-vllm` becomes worth its complexity for the Arc pools (tensor
  parallel, batching) — it slots in as another pool type behind the same router.

## 5. Phases and preconditions

| Phase | Work | Precondition / verification |
|---|---|---|
| 1 | `ollama-intel` pool; guard pinned to it; Pools view; VetoGuard residency check per pool | sentinel suite phase 3 green with the guard on Arc; `/status` shows Arc VRAM |
| 2 | LiteLLM multi-pool deployments + scheduler pre-warm/unload (`auto` pin, first-available) | suite gains "model resident on expected pool" and "user cannot set keep_alive/num_gpu" |
| 3 | cross-app eviction (image/video/speech) | roadmap 7/8 hard gates shipped first |
| 4 | worker role, mesh, router across nodes | second box available; suite run against the farm |
