# Design: portal, single identity, per-user grants, model browser, gallery

Status: **for review** (operator + Gemini) before build. Written 2026-09-24 from the operator's requirements and
the Claude/Gemini exchange on the model browser. Nothing here is deployed.

## Goals (operator)
1. One web portal at `/`: left menu — Chat · Images · Gallery · Speech · Settings (admins also see Hub) — content
   loads in a frame on the right. Dark theme matching Open WebUI / ComfyUI.
2. One identity: the admin is admin everywhere; users get features enabled by an admin; **the admin's settings
   force compliance in every stack beneath the portal, no matter what.**
3. Per-user gallery of ComfyUI output; admins may review anyone's; the page states when admin review is on.
4. Admin-only graphical model browser (HuggingFace + CivitAI) under Hub → Models: thumbnails/previews,
   categories, filters, NSFW toggle (default off), hardware-fit badges, one-click download into the shared store.
5. Users never change what is in memory; they use what is presented, if granted.

## Identity
- **Authelia** (file-backed users, TOTP, groups) behind Caddy `forward_auth`. One login for `/`, apps, Grafana.
- Groups drive everything: `admins`, `chat`, `images`, `images-nsfw`, `speech`, `grafana-viewers`.
- Open WebUI: OIDC to the same IdP (no second password). Grafana: auth-proxy headers, role from group.
- Hub: keeps its own admin login (argon2id + TOTP) as defence in depth for the admin plane; may additionally
  require the `admins` group at the edge.

## Enforcement — where bypass is impossible
The hub is the **single source of truth** (`caddy/hub/state/grants.json`, root-only, written only by the hub):
per-user model allow-list, feature flags (`images`, `images-nsfw`, `speech`), NSFW attribute per exposed model.
Mirroring grants into an app's own settings is for UX only; enforcement happens at points no app can route around:

| Surface | Enforcement point | Mechanism |
|---|---|---|
| Chat / API | LiteLLM hook next to VetoGuard | Open WebUI forwards user identity headers on every request; the hook refuses any model the user is not granted (400 `access_denied`, audited). API keys already carry model lists. |
| Images | Portal proxy in front of ComfyUI | ComfyUI is reachable only through the portal; the proxy refuses without `images`; NSFW-marked models require `images-nsfw`; if no permitted image model is loaded the user sees "no image model available to you". |
| Speech | Portal proxy in front of Fish Speech | same pattern with `speech` |
| Memory | Hub only (unchanged) | users cannot load/unload |
| Open WebUI model list | mirrored from grants via its admin API | cosmetic; the LiteLLM hook is the control |

## Gallery and the image safety gate
- Every generation request passes the portal with the user's identity; outputs are written to `gallery/<user>/`.
- **Prompt gate first:** tripwires + text classifier on the prompt before ComfyUI runs; barred prompts never
  generate. Evidence (serious class): prompt text + metadata, exactly as text vetoes today.
- **Output gate destroys, never stores:** an image classifier evaluates each output before it is written to the
  gallery. A flagged image is deleted immediately — never sealed, never quarantined. What is sealed for the
  serious class: prompt, metadata, verdict, and a **perceptual hash** of the image (PDQ-style) so law enforcement
  can match against known material without the platform holding contraband. This is a legal boundary, not a
  preference; confirm retention of prompt text with counsel for the operator's jurisdiction.
- Gallery page banner when admin review is on: *"Administrator review is enabled: administrators can view images
  in every gallery."* Admin views of other users' galleries are audited.
- ComfyUI stays 503 at the edge until the prompt gate, the image classifier and the gallery enforcement exist and
  pass the sentinel suite (roadmap #8).

## NSFW model files in ComfyUI — per-file attributes, enforced on the workflow (design, 2026-09-24)
A workflow is not NSFW; a **file** is. Every model reference in a ComfyUI workflow is a filename in a known
folder (`CheckpointLoaderSimple.ckpt_name`, `LoraLoader.lora_name`, `VAELoader`, `UNETLoader`, `CLIPLoader`,
`ControlNetLoader`, …), so the gate works on files:

1. **Attribute registry (hub, root-only):** every file under `comfyui/` carries `nsfw: yes | no | unclassified`,
   plus source, hash, licence. The browser sets it at download time from the registry's own flag (CivitAI `nsfw`,
   HF `not-for-all-audiences`); files copied in by hand start **unclassified**. Admin edits it in Models →
   Installed (audited). Unclassified = unavailable to everyone but admins until classified (fail closed).
2. **Enforcement point = the portal proxy in front of ComfyUI's `POST /prompt`.** ComfyUI is reachable only
   through it (`apps` network; `/comfy` is 503 at the edge until this exists). The proxy walks the submitted
   workflow, collects **every string input that names a file in the store** (not just known node classes — so a
   custom "load from path" node cannot slip one through), and refuses the whole prompt (400, audited, user +
   files named) if any referenced file is NSFW/unclassified and the user lacks `images_nsfw`. Workflows that
   reference only SFW files run for anyone with `images`.
3. **Menus follow the grant (UX, not the control):** the proxy filters `/object_info` so a user without
   `images_nsfw` never sees NSFW filenames in dropdowns.
4. **Output gate is independent of the file attribute:** an SFW checkpoint can still produce NSFW output. Every
   image passes the output classifier; illegal → destroyed + sealed metadata (as designed); NSFW for a user
   without the grant → destroyed, audited, not evidence; NSFW for a granted user → gallery.
5. **Prompt gate** (VetoGuard on positive/negative prompt text) runs before any of this, as for chat.
6. Gallery items carry the files/attributes used, so admin review and the user's own purge see them.

## Model browser (Hub → Models → Browse)
Agreed with Gemini after review:
- **Guest-bound telemetry only.** VRAM budget from DCGM/Prometheus and Ollama inside the VM. The guest never
  holds hypervisor (Proxmox) credentials. Intel Arc B60s are not counted until a runtime uses them.
- **Badges, not scrubbing.** Every result shows *Fits / Tight / Won't fit* relative to free VRAM with the current
  classifier resident, from a fuzzy KV-cache band (parameters × quant width + context × layers). Admin decides.
  Hardware fit is operational guidance, not a security control — an admin can always pull by name.
- **Egress silo.** The browser runs on `mgmt` beside `modeld`; `edge` and `backend` keep zero WAN egress.
- **Ingestion safety.** `.safetensors` and GGUF only; every download verified against the registry's SHA-256;
  `.ckpt`/`.pt`/`.bin` pickles refused unless an admin overrides per file (audited).
- **Previews (revised 2026-09-24 by operator decision).** Thumbnails are shown — they are what makes an image/video model browser usable — but only PG/PG-13 registry previews unless NSFW is on, and always proxied through the hub so the admin's browser never contacts a registry. With NSFW off, NSFW listings are not fetched at all. "Blue/red": the CivitAI API key's scope
  decides whether NSFW listings are reachable; the key is stored root-only and encrypted; enabling NSFW requires
  a red-scope key and is audited.
- Downloads land in the shared store (Ollama for GGUF; ComfyUI checkpoints/loras for safetensors) and appear in
  Models → Installed with capability icons; exposing them to users is a separate, audited step.

## Portal shell
- Same-origin iframes; Caddy sets `Content-Security-Policy: frame-ancestors 'self'` (replacing `X-Frame-Options: DENY`).
- Menu from groups; Settings = the user's own MFA/password (via the IdP) and gallery preferences.
- Public `/status` tile (shipped) for everyone.

## Build order
1. Identity (Authelia, groups, TOTP; Caddy forward-auth) — supervised.
2. Portal shell + grants file + LiteLLM access hook + Open WebUI OIDC and mirror.
3. Model browser on `mgmt`.
4. Image classifier + prompt gate for images.
5. ComfyUI behind the portal proxy + gallery + admin-review banner + perceptual-hash evidence.
6. Speech behind the portal proxy.

Each step: acceptance assertions added to `scripts/sentinel_test.py`, changelog entry, Gemini adversarial round.
