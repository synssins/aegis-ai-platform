# Security model

## Principles
1. **Security and safety over convenience.** Anything that weakens the safety pipeline or the network
   split is a console-only, logged change.
2. **Assume the perimeter fails.** The platform does not rely on the LAN being trustworthy.
3. **Nothing unclassified reaches a user.** Inputs and outputs (including streamed output) pass a
   classifier; the classifier failing means the request fails.
4. **Auditable.** Vetoes, hub actions and key operations leave records that contain no content.
5. **Reproducible.** The tracked tree + `.env.example` + `docs/MIGRATION.md` rebuild the platform.

## Threat model
| Actor | Path | Control |
|---|---|---|
| LAN device | 80/443 only | Caddy; API allow-list; per-client virtual keys with rate limits; signup disabled |
| Authenticated chat user | prompts, uploads | VetoGuard tripwire + Llama Guard pre/post; no direct engine path; web fetch off |
| API client | `/v1` | own virtual key, model allow-list, rpm/tpm limits; same VetoGuard path |
| Compromised web container | lateral | cannot reach ollama (backend internal); cannot reach Caddy admin; no docker socket; no caps |
| Compromised hub | Caddy admin API, LiteLLM master key, one request file | can only push the read-only Caddyfile + one templated site file; ask the watchdog for allow-listed start/stop/restart (never stop caddy/hub); no Docker socket anywhere in the stack |
| Brute force on the hub | login | argon2id, mandatory TOTP with replay protection, per-user and per-IP lockout, audit + alert |
| Future tool/MCP servers | tool results | treated as untrusted input; scanned like user text; isolated `tools` network |
| Operator workstation | SSH | (host-level; supervised) key-only auth, scoped sudo |

## Why there is no Docker socket in any container
The Docker socket is root on the host. A container holding it turns any code-execution bug in that container into host compromise — every network split, capability drop and policy file becomes irrelevant. The hub therefore never talks to Docker. It writes one JSON request file; a root service *on the host* (`aegis-watchdog`) reads it, validates it against a fixed allow-list, and acts. The channel is a file in a root-only directory, not a socket or a port, so nothing on any network can reach it.

## Out of scope / known limits
- The lexical tripwire is evadable by paraphrase; the classifier is the control and is itself imperfect.
  Tune with `VETO_GUARD_IGNORE_CATEGORIES` only after reviewing the audit log.
- The host can reach container ports via the Docker bridge gateway. Mitigated by strong keys; a
  host-level `OUTPUT` rule is a supervised follow-up.
- Llama Guard 3 **1B** is used because it fits beside a 26 GB model on 32 GB of VRAM; the 8B model is
  stronger and should replace it when a second GPU class is available for the guard.
- Image generation (planned) must not be enabled without a prompt-side classifier, an output-side
  multimodal classifier, and its own audit log.

## Reporting
Open an issue describing the class of problem. Do not include exploit payloads or harmful content.
