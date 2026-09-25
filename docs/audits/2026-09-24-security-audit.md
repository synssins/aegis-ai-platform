# Security and safety audit — 2026-09-24 (stop-gap fixes)

Independent adversarial review of the whole repository at `e622010` (Claude, with a second independent verification
pass). The full report, including open items, is held privately by the operator. This public record lists what was
fixed on branch `security/stopgap-fixes-zero-retention` and how each fix is tested. Open items are described only at
a high level until they are fixed.

## Fixed

| ID | Severity | Finding | Fix | Tests |
|---|---|---|---|---|
| C1 | Critical | Image, audio and file parts in chat requests were skipped by VetoGuard, so non-text content reached vision models unchecked | Any non-text part in messages, input, prompt, system or provider-native media fields is refused first (400 `unsupported_content`); tool arguments and schemas that merely use the words file/image are not affected | `tests/test_vetoguard.py` NonTextContent; suite 10.1–10.2 |
| H2 (part) | High | Child-safety tripwires could be switched off with the other lists; default classifier was the 1B model | `csam` list and despaced pass always run; default `llama-guard3:8b` in proxy, hub and compose | LockedTripwires; 10.3–10.4 |
| H3 | High | The ComfyUI forward-auth check answered 200 (the password-change page) for invite-code-only sessions, before the images-grant check; ComfyUI's own cross-user API (queue incl. prompts, interrupt, jobs, logs, model listings, add-on managers, shared workflow writes) was reachable | Forward-auth endpoints answer first and grant only fully signed-in sessions holding the grant; those ComfyUI routes are refused at the edge | test_hub ForwardAuth; 10.5–10.6 |
| H4 (part) | High | Image-prompt gate skipped any text ending in a model filename, and checked only the first 60,000 characters | Model-file values must match exactly; oversize text is refused; node classes must be on an allow-list and text-rewriting/loading classes are always refused; destroyed jobs leave no prompt copy in hub memory or ComfyUI history | test_hub ImagePromptGate |
| M5 (part) | Medium | `/tts` had no authentication | Forward-auth with the `speech` grant | ForwardAuth; 10.7 |
| M1 | Medium | Sealed evidence stored full vetoed content (operator decision: zero retention) | Evidence store, handoff, key and snippets removed; `scripts/evidence-purge.sh` for old records | ZeroRetention (both files); 3.14, 3.15, 8.5 |
| M2 (part) | Medium | Refused content persisted elsewhere: LiteLLM failed-request log, portal chat browser storage, classifier-answer echo in the audit log | `disable_error_logs`; portal stores a turn only after the gate has released its answer (input or output veto, error, abort → nothing stored); unreadable verdicts recorded as verdict words or a length only; purge script empties old error-log rows and scrubs old audit fields | ZeroRetention; 10.8–10.9 |

Every offline test fails against the pre-fix code and passes after it (`python3.12 -m unittest discover -s tests`).

## Open (planned order)
1. Full-history classification (older turns are currently checked by the tripwire only).
2. Classifier identity pinning and a dedicated classifier engine.
3. Setup-wizard hardening.
4. Single sign-on with MFA for every front end; per-user identity forwarded to the gateway.
5. Hub privilege split (gateway configuration, engines, policy).
6. Network egress, container and supply-chain hardening.
7. Open WebUI's own chat history and document storage (outside the gate); a ComfyUI route allow-list and per-user
   workflow storage.
