# Agy (Gemini) adversarial review, round 5 — VetoGuard 2.6 — 2026-09-24

Permission-gated print mode (JSON output), read-only. Paths sanitised.

Based on a defensive security code review of [veto_filter.py] (revision 2.6), below are the concrete weaknesses that remain or were newly introduced in revision 2.6.

---

### 1. Silent Omission of Oversized Multipart Block Leaves Allows Inspection Bypass

* **Severity**: High
* **Title**: Silent Truncation/Omission of Large Leaves in Unknown Multipart Blocks
* **Mechanism**: In revision 2.6, [_content_to_text] was modified to collect string leaves from unknown multipart content blocks:
  ```python
  if not known and p.get("type") not in ("image_url", "input_image", "input_audio", "audio", "file"):
      parts.extend(x for x in _string_leaves(p, 0) if len(x) < 100_000)
  ```
  If an unknown block contains a string leaf `x` where `len(x) >= 100_000`, the condition `len(x) < 100_000` evaluates to `False`. The string is silently dropped rather than truncated or rejected. If the request also contains any benign text in another part (so `view.all_texts` is non-empty), the request is deemed valid, passes tripwires and Llama Guard, and LiteLLM forwards the uninspected payload of $\ge 100{,}000$ characters to the model.
* **Fix**: Do not silently drop leaves exceeding the size threshold. Truncate them for scanning (e.g., `x[:100_000]`) or raise [SchemaBudgetExceeded] so the gate fails closed.

---

### 2. Base64 Filter Evasion via Non-Printable or Null Byte Insertion

* **Severity**: High
* **Title**: Discarding Valid Decoded Base64 Payloads on Non-Printable Characters
* **Mechanism**: In [_decoded_b64_fragments]:
  ```python
  if dec.strip() and all(ch.isprintable() or ch in "\n\t\r" for ch in dec):
      out.append(dec)
  ```
  If a base64-encoded payload contains a single non-printable byte or null byte (`\x00`, `\x08`, `\x1b`, etc.) anywhere in the string, `all(...)` evaluates to `False`. The entire decoded payload is discarded and excluded from `out`. Consequently, neither the regex tripwires nor Llama Guard ever inspect the decoded payload. Downstream LLMs typically ignore or strip null and control bytes and process the underlying prompt unobstructed.
* **Fix**: Filter or sanitize non-printable characters rather than discarding the entire decoded text (e.g., stripping non-printable characters or verifying that the ratio of printable characters exceeds a threshold, and scanning the sanitized text).

---

### 3. System Instructions in Standard `messages` Format Bypass Llama Guard

* **Severity**: High
* **Title**: Exclusion of `messages` System Role from Classifier Evaluation
* **Mechanism**: In rev 2.5, top-level `data["system"]` was added to `new_segment` to ensure it reaches the classifier. However, in standard chat completion schemas, system prompts are passed inside `data["messages"]` with `role: "system"` (typically at index 0). In [RequestView.__init__]:
  ```python
  last_user_idx = max((i for i, m in enumerate(msgs) if m.get("role") == "user" and _content_to_text(m.get("content")).strip()), default=0)
  self.new_segment = []
  for m in msgs[last_user_idx:]:
  ```
  `last_user_idx` resolves to the subsequent user turn (e.g., index 1). As a result, `msgs[0]` is excluded from `new_segment` and `new_texts`, bypassing chunk-level classification. In the conversation window `w`, Llama Guard only evaluates the final turn in context, so it never evaluates the system turn either. A disallowed instruction placed in a `role: "system"` message in `messages` is never evaluated by Llama Guard.
* **Fix**: Ensure system messages extracted from `msgs` are added to `new_segment` (or `new_texts`) for chunk classification, consistent with `data.get("system")`.

---

### 4. Synthetic `(continue)` User Turn Neutralizes Context Evaluation for Assistant Prefills

* **Severity**: High
* **Title**: Multi-Turn Context Bypass on Assistant-Prefill Requests
* **Mechanism**: In [classify_request]:
  ```python
  w = _window(view.turns)
  if len(w) > 1:
      if w[-1]["role"] != "user":
          w = w + [{"role": "user", "content": "(continue)"}]
      calls.append(w)
  ```
  When an API client submits an assistant prefill (a request ending in an assistant turn intended to elicit a continuation of a disallowed response), `w[-1]["role"]` is `"assistant"`. Line 571 appends `{"role": "user", "content": "(continue)"}`. Because Llama Guard's prompt architecture evaluates the safety of only the *last* turn in a conversation, Llama Guard assesses whether the synthetic string `"(continue)"` is safe. Since `"(continue)"` is benign, Llama Guard returns `safe`, and the preceding assistant prefill is never evaluated in context.
* **Fix**: Do not append a synthetic user turn when the conversation ends in an assistant message; allow Llama Guard to evaluate the assistant turn in context directly.

---

### 5. Shared Global Client and Semaphore Race Condition Across Async Event Loops

* **Severity**: Medium
* **Title**: Cross-Loop State Corruption and Connection Leak in Multi-Threaded Deployments
* **Mechanism**: In [_client] and [_sem], single global variables `_CLIENT`, `_CLIENT_LOOP`, `_SEM`, and `_SEM_LOOP` are updated whenever `loop is not _CLIENT_LOOP`. In LiteLLM deployments running across multiple worker threads or thread-pool event loops, concurrent requests on different threads overwrite these shared references. When a coroutine on loop A attempts to invoke an `httpx.AsyncClient` or `asyncio.Semaphore` created on loop B, Python raises a `RuntimeError` (`Future attached to a different loop`). [_guard_call] catches this and raises [GuardUnavailable], causing intermittent 503 denials of service. Additionally, orphaned clients are never awaited for closure (`aclose()`), leaking connections.
* **Fix**: Maintain client and semaphore instances in a thread-local structure (`threading.local`) or a loop-indexed dictionary mapping `AbstractEventLoop` to its dedicated client and semaphore.

---

### 6. ThreadPool Exhaustion Denial of Service via `asyncio.to_thread`

* **Severity**: Medium
* **Title**: Global ThreadPool Worker Starvation on Tripwire Timeout
* **Mechanism**: In [tripwires]:
  ```python
  return await asyncio.wait_for(asyncio.to_thread(tripwire_check, texts, lists), timeout=SCAN_BUDGET_S)
  ```
  `asyncio.to_thread` offloads regex scanning to the default global `ThreadPoolExecutor`. In Python, `asyncio.wait_for` timing out does not cancel or interrupt the synchronous worker thread. If requests containing long inputs (near `MAX_SCAN_CHARS = 2_000_000`) or slow regex evaluations occupy the thread pool workers, a small number of concurrent requests will saturate all executor threads. Once saturated, all subsequent calls to `asyncio.to_thread` across the entire application remain queued; their 5-second `wait_for` timers expire before execution starts, causing every request to fail with a 400 rejection.
* **Fix**: Use a dedicated, bounded `ThreadPoolExecutor` separate from the default loop executor, and limit `MAX_SCAN_CHARS` per total request rather than per individual string segment.

---

### 7. Unbounded Chunk Buffering Memory Exhaustion in Streaming Hook

* **Severity**: Medium
* **Title**: Memory DoS via High-Volume Empty Streaming Chunks
* **Mechanism**: In [async_post_call_streaming_iterator_hook], `buffered.append(chunk)` appends every upstream chunk to an in-memory list. The cutoff check `if size > MAX_OUTPUT_CHARS:` only accumulates lengths of extracted content strings (`piece`, `args`, etc.). If an upstream response transmits thousands of non-text chunks (e.g. empty deltas, metadata, keep-alives), `size` remains below the threshold while `buffered` expands without bounds, leading to high memory pressure or an Out-Of-Memory termination.
* **Fix**: Enforce a maximum chunk count limit (e.g. `if len(buffered) > MAX_CHUNKS: withheld = ["OUTPUT_BUFFER_CAP"]; break`).

---

### 8. Multiline Base64 Detector Rejects Indented Continuation Lines

* **Severity**: Low
* **Title**: Regex Failure on Indented Multiline Base64 Blocks
* **Mechanism**: In [veto_filter.py], [B64_BLOCK_RE] matches wrapped base64 lines:
  ```python
  B64_BLOCK_RE = re.compile(r"(?:[A-Za-z0-9+/_-]{4,}={0,2}[ \t]*\r?\n){1,}[A-Za-z0-9+/_-]{4,}={0,2}")
  ```
  The pattern allows trailing whitespace before a newline (`[ \t]*\r?\n`), but requires the subsequent line to begin immediately with base64 characters. If a multiline base64 block is formatted inside structured text (such as JSON or YAML) with leading indentation spaces on continuation lines, the regex fails to match. If line breaks fall across token boundaries, single-line extraction fails to reconstruct the payload.
* **Fix**: Allow optional leading whitespace on continuation lines (e.g., `(?:[A-Za-z0-9+/_-]{4,}={0,2}[ \t]*\r?\n){1,}[ \t]*[A-Za-z0-9+/_-]{4,}={0,2}`).

---

VERDICT: High severity vulnerabilities remain that permit inspection bypasses, silent payload omissions, and denial-of-service conditions.
