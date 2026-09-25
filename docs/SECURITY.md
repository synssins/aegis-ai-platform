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
| Compromised hub | Caddy admin API, LiteLLM master key, one request file | **Today this is broad** (audit 2026-09-24, H6): code running in the hub can load any Caddy configuration, write site files the Caddyfile imports, change the safety policy, and reach the model engines. It cannot reach the Docker socket; the watchdog only starts/stops/restarts allow-listed containers (never stops caddy/hub). Splitting the hub and cutting these paths is planned. |
| Brute force on the hub | login | argon2id, mandatory TOTP with replay protection, per-user and per-IP lockout, audit + alert |
| Future tool/MCP servers | tool results | treated as untrusted input; scanned like user text; isolated `tools` network |
| Operator workstation | SSH | (host-level; supervised) key-only auth, scoped sudo |
| Spoofed network identity | claimed IP / user agent | never trusted as identity: the audit names the **API key alias** (cryptographic) and, once device certificates are enabled, the **client-certificate fingerprint** (requires the device's private key) |

## Why there is no Docker socket in any container
The Docker socket is root on the host. A container holding it turns any code-execution bug in that container into host compromise — every network split, capability drop and policy file becomes irrelevant. The hub therefore never talks to Docker. It writes one JSON request file; a root service *on the host* (`aegis-watchdog`) reads it, validates it against a fixed allow-list, and acts. The channel is a file in a root-only directory, not a socket or a port, so nothing on any network can reach it.

## Zero retention of vetoed content
Operator decision (2026-09-24): prevent entirely rather than capture. When anything is vetoed, nothing about its
content is stored — not the request, not the output, not matched text, not an image, hash or snippet. The audit log
keeps metadata only (time, stage, category, key alias, model, device fingerprint). Earlier versions kept sealed
evidence records; `scripts/evidence-purge.sh` destroys them. See `docs/EVIDENCE.md`. Open WebUI keeps its own chat history (including refused messages) — a known open item; the portal chat does not.

## Out of scope / known limits
- The lexical tripwire is evadable by paraphrase; the classifier is the control and is itself imperfect.
  Tune categories in the hub only after reviewing the audit log.
- The host can reach container ports via the Docker bridge gateway. Mitigated by strong keys; a
  host-level `OUTPUT` rule is a supervised follow-up.
- The classifier is only as good as its model; Llama Guard 3 8B is the default (`VETO_GUARD_MODEL`). See `docs/SAFETY.md`.
- Image generation (planned) must not be enabled without a prompt-side classifier, an output-side
  multimodal classifier, and its own audit log.

## Reporting
Open an issue describing the class of problem. Do not include exploit payloads or harmful content.

## Open items from the 2026-09-24 audit
Fixed in `docs/audits/2026-09-24-security-audit.md` (stop-gaps). Still open, in planned order: full-history
classification, classifier identity pinning, setup-wizard hardening, single sign-on with MFA for every front end,
hub privilege split, and network/supply-chain hardening. Details are kept out of this public file until fixed.
