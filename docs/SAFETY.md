# Safety: how VetoGuard works

VetoGuard is the LiteLLM hook every request and every response passes through (`proxy/veto_filter.py`).
It is **mandatory and fail-closed**: if any layer cannot run, the request is refused.

## Layers
1. **Lexical tripwire.** Regex over normalised text (NFD → strip combining/format chars → NFKC → confusable
   mapping → whitespace collapse), plus decoded base64 (standard and URL-safe, including line-wrapped) and a
   despaced pass for unambiguous tokens. Built-in lists: sentinel (for tests), CSAM terms, malware intent; the
   administrator may add patterns (checked for catastrophic backtracking; every scan runs under a 5-second
   budget on a bounded executor — a timeout is a refusal, never a pass).
2. **Classifier.** A safety model served by Ollama on the backend network — Llama Guard 3 by default. Runs on
   the request (chunked with overlap, plus the last 8 turns as a real multi-turn conversation) and on the
   response. **Streaming is buffered:** nothing reaches the client until the whole response is classified.
3. **Policy.** `proxy/policy/veto-policy.json`, written only by the hub, hot-reloaded. Configurable: classifier
   model, blocked categories, tripwire toggles/extra patterns, retention, evidence, diagnostics. Not
   configurable: the classifier stage, fail-closed behaviour, and category S4 (always blocked, always immutable,
   always sealed as evidence).

## What is scanned
Latest user turn and everything after it (assistant prefill, tool results, tool-call arguments), every earlier
message (client history is untrusted), `system`/`developer` messages and the top-level `system` field, `prompt`,
`input`, tool/function schemas (keys and values), multimodal text parts, and on output: content, reasoning
fields, tool calls — for every choice when `n > 1`.

## Categories
Codes are Llama Guard 3's hazard taxonomy (S1–S14). Definitions: the Llama Guard 3 model card,
<https://github.com/meta-llama/PurpleLlama/blob/main/Llama-Guard3/8B/MODEL_CARD.md>.
Default policy: **blocked** S1, S2, S3, S4, S9, S10, S11; **allowed** S5, S6, S7, S8, S12, S13, S14.
Operator intent: illegal and protected-class content never passes; adult content may.

## Verdict adapters
Each safety-model family needs an adapter (request template + answer parser). Llama Guard ships. A model without
an adapter, or an answer the adapter cannot parse, is refused (`503 guard_no_adapter` /
`guard_verdict_unparseable`) and the audit records what came back and what was expected.

## Responses to callers
| Situation | HTTP | `code` |
|---|---|---|
| policy veto (input or output) | 400 | `veto_triggered` |
| classifier unreachable | 503 | `guard_unavailable` |
| unreadable verdict / no adapter | 503 | `guard_verdict_unparseable` / `guard_no_adapter` |
| input too large to classify | 413 | `prompt_too_long_for_guard` |
| streamed response withheld | 200 stream ending in one chunk `[Response withheld by policy: veto_triggered]`, `finish_reason: content_filter` |

A conversation whose history contains a vetoed turn stays refused; start a new chat.

## Audit, retention, evidence
- Every veto: `proxy/audit/veto-audit.jsonl` — time, stage, reason, category codes, model, key alias, device
  fingerprint when present. Never content.
- Entries in the immutable set (S4 always; S3, S10, S11 and CSAM tripwires by default) cannot be cleared from
  the hub; they expire by time only (minimum 90 days).
- Vetoes in the evidence set (S4 always; CSAM tripwires always) produce a sealed record — see `docs/EVIDENCE.md`.
- Optional diagnostics (default off): a 160-character snippet of flagged *output*, never for S4.

## Choosing a classifier
Llama Guard 3 **8B** is materially better than 1B on paraphrased, obfuscated and multilingual content, and it is
the default recommendation. It needs ~6 GB VRAM beside the main model; load the main model first. The hub's
Metrics page and the dashboard show residency; a classifier that is not resident loads on the next request.

## Limits, honestly
Regex is a tripwire, not a boundary. The classifier is imperfect and English-strongest. Both are logged so the
policy can be tuned from evidence rather than guesswork. Adversarial reviews and their outcomes are kept in
`docs/tests/agy-vetoguard-review-*.md`.
