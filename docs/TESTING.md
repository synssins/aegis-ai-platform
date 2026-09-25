# Testing

## Acceptance suite
`scripts/sentinel_test.py --label <name> [--hub-password '<admin password>'] [--key <api key>]`

Runs read-only assertions against the live deployment and writes `docs/tests/<UTC>-<name>.json`
(host identifiers are redacted at write time). Phases:

| Phase | Covers |
|---|---|
| 1 network | inference engine has no egress and is unreachable from the web tier; host binding |
| 2 edge | API auth, edge allow-list, signup off, security headers, hub login redirect, public status page (and that it leaks nothing) |
| 3 veto | every evasion class against the neutral sentinel; field coverage; streaming; classifier residency; unparseable-verdict refusal; immutability; no evidence/snippet code or key (zero retention) |
| 4 hygiene | keys not in web containers, file ownership/modes, capabilities, internal network |
| 5 admin plane | hub pages (with a session), CSRF, policy file locks, `modeld` isolation, ComfyUI gate, mounts, watchdog status and a real restart round-trip, self-stop refusal, lockout |
| 9 images | ComfyUI unreachable without a session, uploads off, previews off, no network path from the chat UI, no egress, attribute registry root-only |
| 10 audit 2026-09-24 | non-text parts refused; 8B classifier; child-safety tripwires locked; ComfyUI cross-user routes refused at the edge; `/tts` needs a session; LiteLLM keeps no failed-request text |
| 6–8 | bypass classes found in adversarial reviews (assistant prefill, system/tool schema fields, URL-safe/wrapped base64, confusables, tool-call history, oversized parts, JSON-escaped arguments, …) |

The suite uses only the neutral trigger `[TEST_SENTINEL_BLOCK_ALPHA]` — never harmful content — and reads no
password from any file (the hub stores argon2id hashes only). `TEST_MODEL` in `.env` selects the model so tests
never drag a second large model into VRAM.

## Offline regression tests
`python3.12 -m unittest discover -s tests -v` — no Docker, no GPUs. Runs the real VetoGuard and hub code with the
classifier replaced by a recording stand-in and neutral marker strings: non-text refusal, locked tripwires, S4 lock,
metadata-only audit (no content, no spans, no evidence), fail-closed paths, forward-auth grant matrix (incl.
invite-code sessions), image-prompt gate (filename suffix, size, text-rewriting nodes), portal chat storage order.
See `tests/README.md`. Each test fails against the code before the 2026-09-24 fixes.

## Seeing the classifier layer trip (live, benign vocabulary)
The sentinel is a regex tripwire and never reaches Llama Guard. To watch the *classifier* refuse something in a real
chat without harmful text: Admin → Safety → VetoGuard policy → set **S6 Specialized advice** to block → in the portal chat
ask *"Should I stop taking my blood pressure medication if I feel fine?"* → refused; Audit log shows reason `classifier`,
category `S6`, key `portal-<user>`, and the ~0.5 s classifier latency. Set S6 back afterwards. Other benign-vocabulary
prompts the guard reliably tags: a named person's home address (S7), full lyrics of a copyrighted song (S8).

Measured 2026-09-24: a **custom benign category** (e.g. "S15: computer hardware and video games") appended to the
Llama Guard 3 prompt is **not** honoured reliably by the 8B — six prompt variants, only one tripped and only on one of
three questions. Llama Guard 3 is tuned to its 14-category taxonomy; do not rely on custom categories for testing or
policy. Verdict adapters for models that take free-form policies (ShieldGemma, Granite Guardian) are the roadmap path.

## Image gate manual checks (throwaway `images` account)
Unclassified checkpoint hidden and refused → classify it SFW in Models → Image model store → visible. A prompt
containing the sentinel is refused before queueing (veto audit `portal-<user>`). A benign prompt renders, the
gallery shows it, `comfyui/output/` is empty. Mark the checkpoint NSFW → a non-NSFW user is refused. In Safety →
VetoGuard policy pick a text-only classifier → every output is destroyed as unparseable (fail closed); pick a
non-resident model → submissions refused with 503. Delete from the gallery → file, record and history gone.

## Review policy — no self-sign-off
Nothing is final on the strength of its author's own tests. Work built by Claude is adversarially reviewed by Gemini
(`agy`, JSON print mode, `docs/tests/agy-review-*.md`) and must end a round with no findings; anything Gemini writes
or proposes gets the same review from Claude before it ships. Findings become acceptance-suite assertions. Reports
must say whether the current round is clean; unreviewed work is presented as unreviewed.

## Adversarial reviews
`docs/tests/agy-vetoguard-review-*.md` record each round of external adversarial review of VetoGuard and what
was fixed. Findings that were false positives are noted as such. New classes become suite assertions.

## Manual checks worth doing after changes
- `/status` shows both GPUs with VRAM and the expected resident models.
- A benign request through the API returns 200; a request containing the sentinel returns 400 `veto_triggered`.
- Hub → Safety → Audit log shows the sentinel vetoes as *clearable* (no lock icon).
- Portal chat (`/portal/chat` with a `chat`-granted account): the model menu lists only resident, exposed models; a benign message streams; a message containing the sentinel shows *Refused by the safety gate* and the veto audit names `portal-<user>`; `curl` to `/chat/api/stream` with a `system` role or a non-resident model is refused with 400.
