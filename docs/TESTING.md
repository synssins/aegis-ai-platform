# Testing

## Acceptance suite
`scripts/sentinel_test.py --label <name> [--hub-password '<admin password>'] [--key <api key>]`

Runs read-only assertions against the live deployment and writes `docs/tests/<UTC>-<name>.json`
(host identifiers are redacted at write time). Phases:

| Phase | Covers |
|---|---|
| 1 network | inference engine has no egress and is unreachable from the web tier; host binding |
| 2 edge | API auth, edge allow-list, signup off, security headers, hub login redirect, public status page (and that it leaks nothing) |
| 3 veto | every evasion class against the neutral sentinel; field coverage; streaming; classifier residency; unparseable-verdict refusal; immutability/evidence gating |
| 4 hygiene | keys not in web containers, file ownership/modes, capabilities, internal network |
| 5 admin plane | hub pages (with a session), CSRF, policy file locks, `modeld` isolation, ComfyUI gate, mounts, watchdog status and a real restart round-trip, self-stop refusal, lockout |
| 6–8 | bypass classes found in adversarial reviews (assistant prefill, system/tool schema fields, URL-safe/wrapped base64, confusables, tool-call history, oversized parts, JSON-escaped arguments, …) |

The suite uses only the neutral trigger `[TEST_SENTINEL_BLOCK_ALPHA]` — never harmful content — and reads no
password from any file (the hub stores argon2id hashes only). `TEST_MODEL` in `.env` selects the model so tests
never drag a second large model into VRAM.

## Adversarial reviews
`docs/tests/agy-vetoguard-review-*.md` record each round of external adversarial review of VetoGuard and what
was fixed. Findings that were false positives are noted as such. New classes become suite assertions.

## Manual checks worth doing after changes
- `/status` shows both GPUs with VRAM and the expected resident models.
- A benign request through the API returns 200; a request containing the sentinel returns 400 `veto_triggered`.
- Hub → Safety → Audit log shows the sentinel vetoes as *clearable* (no lock icon).
