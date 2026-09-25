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
   model, blocked categories, tripwire toggles/extra patterns, audit retention. Not configurable: the classifier
   stage, fail-closed behaviour, category S4 (always blocked, audit entries always immutable), the child-safety
   tripwire list (always on), the refusal of non-text content, and zero retention of vetoed content.

## What is refused before scanning
Any request carrying an image, audio, video or file part (OpenAI `image_url`/`input_image`/`input_audio`/`file`,
Ollama-style `images`, …) is refused with 400 `unsupported_content`. Llama Guard 3 reads text only, so such content
could not be checked before a model saw it; refusing is the only way to guarantee no inference on it. Safe image
and document input is planned (`docs/designs/multimodal-input.md`, roadmap #13).

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

## Audit and retention (zero retention)
- Every veto: `proxy/audit/veto-audit.jsonl` — time, stage, reason, category codes, model, key alias, device
  fingerprint when present. Never content.
- Entries in the immutable set (S4 always; S3, S10, S11 and CSAM tripwires by default) cannot be cleared from
  the hub; they expire by time only (minimum 90 days).
- **VetoGuard, the hub and LiteLLM store nothing about vetoed content** — no request text, no output text, no
  matched spans, no evidence records, no snippets; LiteLLM's own failed-request log is disabled (`disable_error_logs`);
  the portal chat keeps a turn in the browser only after the gate has released its answer. Open WebUI keeps its own chat history (including refused messages) — a known open item; the portal chat does not. See
  `docs/EVIDENCE.md`.

## Choosing a classifier
Llama Guard 3 **8B** is materially better than 1B on paraphrased, obfuscated and multilingual content, and it is
the default (compose `VETO_GUARD_MODEL`, hub default policy). It needs ~6 GB VRAM beside the main model; load the main model first. The hub's
Metrics page and the dashboard show residency; a classifier that is not resident loads on the next request.

## Limits, honestly
The classifier sees the newest user turn and everything after it in full, plus the last 8 turns as context (long
turns cut to their head and tail); older history is checked by the tripwire only. Closing this gap is the next
planned change (audit 2026-09-24, H1).
Regex is a tripwire, not a boundary. The classifier is imperfect and English-strongest. Both are logged so the
policy can be tuned from evidence rather than guesswork. Adversarial reviews and their outcomes are kept in
`docs/tests/agy-vetoguard-review-*.md`.

## Image generation (ComfyUI)
Same posture as text, applied three times per workflow (see `docs/HUB.md` → Images and Gallery): prompt texts
through VetoGuard; model files gated by a per-file NSFW attribute against the account's `images_nsfw` grant;
every output judged by a vision model before anyone can see it. Illegal / minor content is destroyed and only a
metadata audit entry remains (zero retention); NSFW without the grant is destroyed;
an unreadable verdict destroys. ComfyUI is reachable only through the hub's gate, has no egress, and the chat UI
has no route to it. Known limits: the output classifier is a general vision model, not a hash-matching CSAM
detector — the prompt gate and the destroy-on-doubt policy are the primary controls; uploads (img2img) pass the
same classifier before ComfyUI can read them and are owned per account.
