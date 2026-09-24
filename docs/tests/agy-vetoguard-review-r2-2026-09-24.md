# Agy (Gemini) adversarial review, round 2 — VetoGuard 2.3 — 2026-09-24

Permission-gated print mode (JSON output), read-only. Paths sanitised.

# Defensive Security Code Review: `VetoGuard` (Revision 2.3)

This review analyzes [veto_filter.py] focusing on vulnerabilities that are still present or newly introduced in revision 2.3. Attack shapes are described abstractly without harmful content.

---

## 1. Request Field Coverage & Extraction

### 1.1 Multi-Turn Conversation History Bypass via Turn Truncation
- **Severity**: Critical
- **Location**: [`collect_request_text`]
- **Mechanism**: Lines 253–254 compute `last_user` as the index of the final message with `role == "user"` and define `scope = msgs[last_user:]`. All conversation turns prior to `last_user` (except `system` and `developer` messages) are discarded. In multi-turn chat completions, an attacker can place a disallowed instruction or payload setup in an earlier user or assistant turn (e.g., `messages[0]`), followed by a benign continuation prompt (e.g., `messages[2] = {"role": "user", "content": "Proceed with step 1"}`). `VetoGuard` scans only the final turn, which is lexically clean and deemed safe by Llama Guard. The upstream model receives the full conversation history and executes the disallowed instruction.
- **Fix**: Scan all conversation messages (`msgs`), or at minimum all user, assistant, and tool turns across the request history rather than slicing from `last_user`.

### 1.2 Fail-Open on Empty or Non-Standard Extracted Text
- **Severity**: Critical
- **Location**: [`async_pre_call_hook`] & [`_content_to_text`]
- **Mechanism**: In `async_pre_call_hook`, line 441 executes:
  ```python
  texts = collect_request_text(data)
  if not texts:
      return data
  ```
  If `texts` evaluates to empty, the pre-call hook returns `data` immediately, bypassing both lexical tripwires and the Llama Guard classifier. 
  Furthermore, `_content_to_text` (lines 214–218) only extracts array elements where `p.get("type") == "text"`. Content parts utilizing alternative block types supported by LiteLLM or upstream providers (e.g., `input_text`, `document`, `tool_result`, or dictionary parts where `type` is omitted) evaluate to empty strings. The request passes through completely uninspected, directly contradicting the fail-closed design requirement.
- **Fix**: Fail closed when `data` contains messages or payload fields but `collect_request_text` produces no evaluatable text. Expand `_content_to_text` to extract textual content from all content block types, including `input_text` and nested document/tool blocks.

### 1.3 Schema Truncation at Arbitrary Depth
- **Severity**: Medium
- **Location**: [`_schema_text`]
- **Mechanism**: Tool schemas are parsed with a hard limit `if depth > 8: return ""`. Standard JSON schemas for structured function calls frequently exceed 8 nesting levels (`tools` -> tool -> `function` -> `parameters` -> `properties` -> object -> `properties` -> inner object -> `properties` -> field description). Malicious steering instructions or prompt injections placed in schema descriptions at depth $\ge 9$ are dropped from safety scanning while remaining visible to the target model.
- **Fix**: Increase the recursion depth limit (e.g., to 24) or traverse schemas iteratively with a total node/character cap rather than a shallow recursion cutoff.

---

## 2. Response & Tool-Call Path

### 2.1 Complete Filter Bypass on Dictionary Responses
- **Severity**: Critical
- **Location**: [`async_post_call_success_hook`]
- **Mechanism**: The hook extracts outputs via `for c in getattr(response, "choices", []) or []:`. When LiteLLM returns responses as dictionary structures (e.g., under `return_response_as_dict=True` or specific provider pathways), `getattr(response, "choices", [])` returns `[]`. The `try` block completes without error, leaving `outputs = []`. Because `outputs` is empty, `_check_output` evaluates empty input, returning `None`. The uninspected response is returned to the client without executing tripwires or classifiers.
- **Fix**: Support both dictionary and attribute-based access:
  ```python
  choices = response.get("choices", []) if isinstance(response, dict) else getattr(response, "choices", [])
  ```

### 2.2 Uninspected Reasoning / Thinking Content
- **Severity**: High
- **Location**: [`async_post_call_success_hook`] & [`async_post_call_streaming_iterator_hook`]
- **Mechanism**: Modern reasoning models stream output in `delta.reasoning_content`, `delta.reasoning`, or `delta.thinking` prior to or alongside `delta.content`. In both the streaming and non-streaming hooks, `VetoGuard` inspects only `content` and `tool_calls`. Any disallowed material generated within the reasoning field is neither scanned by tripwires nor evaluated by Llama Guard, and is released directly to the client.
- **Fix**: Extract and concatenate `reasoning_content` and related fields from both `message` and `delta` objects during output validation.

### 2.3 Escaped JSON Sequences in Tool-Call Arguments Evade Lexical Tripwires
- **Severity**: Medium
- **Location**: [`_tool_calls_text`]
- **Mechanism**: Tool call arguments are extracted as raw serialized JSON strings. Punctuation and whitespace delimiters in JSON are frequently backslash-escaped (e.g., `\\n`, `\\u0020`, `\\t`). `normalise` does not unescape JSON string encodings. Because lexical patterns (such as `MALWARE_PATTERNS`) depend on regex `\s*` or `\b`, escaped delimiter sequences prevent pattern matching while remaining fully executable by the downstream tool.
- **Fix**: Decode JSON string values or apply `json.loads` / unicode unescaping on extracted arguments prior to running lexical tripwires.

---

## 3. Streaming Safety Gaps

### 3.1 Multi-Choice (`n > 1`) Streaming Safety Bypass
- **Severity**: Critical
- **Location**: [`async_post_call_streaming_iterator_hook`]
- **Mechanism**: Line 506 inspects only the first choice: `delta = getattr(choices[0], "delta", None)`. When a caller requests multiple completions (`n > 1`), chunks contain deltas across multiple indices (`choices[1]`, `choices[2]`, etc.). Text and tool deltas for indices $> 0$ are completely ignored. If choice 0 is safe but choice 1 contains disallowed material, `_check_output` approves the buffer, and lines 529–531 yield all chunks in `buffered` to the caller, releasing the uninspected candidate.
- **Fix**: Iterate over all entries in `choices`, maintaining separate delta aggregation buffers per choice index, and validate each choice before releasing the stream.

### 3.2 Stream Crashing (`IndexError`) on Empty Initial Choices
- **Severity**: High
- **Location**: [`async_post_call_streaming_iterator_hook`]
- **Mechanism**: Many streaming providers emit an initial metadata chunk where `choices` is an empty list `[]`. When an unsafe response is withheld, the synthetic replacement logic executes:
  ```python
  first = copy.deepcopy(buffered[0])
  first.choices[0].delta.content = WITHHELD_MSG
  ```
  If `buffered[0].choices` is empty, `first.choices[0]` raises `IndexError`. The enclosing `except Exception:` catches this and executes `return`, prematurely terminating the generator. The client receives an abrupt connection termination without the required synthetic `content_filter` chunk or withheld notice.
- **Fix**: Locate the first chunk in `buffered` that actually contains a choice element, or synthesize a clean standalone chunk object rather than mutating `buffered[0]`.

### 3.3 Full-Stream Buffering Denial of Service
- **Severity**: Medium
- **Location**: [`async_post_call_streaming_iterator_hook`]
- **Mechanism**: The hook buffers entire response streams in process memory up to `MAX_OUTPUT_CHARS = 400_000` characters per stream. Under hundreds of concurrent streaming connections, this creates significant memory pressure. Furthermore, streaming latency is degraded because tokens cannot be emitted iteratively; time-to-first-token is equal to the time to generate the full completion plus downstream classifier latency.
- **Fix**: Document this design trade-off or enforce a tight aggregate concurrency limit on concurrent buffered streams.

---

## 4. Normalisation & Tripwire Gaps

### 4.1 Base64 Classifier Omission (False Changelog Claim)
- **Severity**: Critical
- **Location**: [`_candidates`] & [`classify_request`]
- **Mechanism**: Revision 2.3 docstring claims: *"decodes standard + URL-safe base64 and feeds decoded text to the classifier too"*. In the code, `_candidates` is called exclusively within [`scan`] and [`scan_despaced`] for regex tripwires. `classify_request` receives raw `texts` directly from `collect_request_text(data)`. Decoded base64 content is **never** passed to Llama Guard. Disallowed instructions encoded in base64 that do not match the narrow lexical tripwire patterns completely bypass the classifier.
- **Fix**: Append valid decoded base64 fragments to `texts` inside `collect_request_text` so that both the classifier and tripwires receive the decoded content.

### 4.2 Base64 Decoding Corruption from Whitespace Stripping
- **Severity**: High
- **Location**: [`_decoded_b64_fragments`]
- **Mechanism**: For inputs under 200,000 characters, line 197 strips all whitespace: `re.sub(r"[\r\n\t ]", "", text)`. When an unpadded base64 payload is adjacent to standard text (e.g., `"prefix cmV2ZXJzZSBzaGVsbA suffix"`), space removal concatenates the surrounding words into the base64 string. Because base64 alignment depends on 4-byte boundaries, boundary distortion causes `base64.b64decode(..., validate=True)` or UTF-8 decoding to fail, discarding the fragment.
- **Fix**: Match base64 tokens with word/whitespace boundaries on the original text rather than globally collapsing whitespace across the entire string.

### 4.3 Short Base64 Payloads Ignored
- **Severity**: Medium
- **Location**: `B64_RUN_RE` ([line 177])
- **Mechanism**: `B64_RUN_RE = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")` ignores any base64 string shorter than 24 characters. A 24-character base64 string decodes to $\approx 18$ bytes. Disallowed keywords or command strings shorter than 18 bytes encoded in base64 are completely ignored by `_decoded_b64_fragments`.
- **Fix**: Lower the length threshold (e.g., to 12 or 16 characters) and validate structural padding.

### 4.4 Incomplete Confusables & Missing Lowercase Cyrillic
- **Severity**: Medium
- **Location**: `CONFUSABLES` ([lines 180–184]) & `NON_ALNUM_RE` ([line 176])
- **Mechanism**: The `CONFUSABLES` mapping includes uppercase Cyrillic letters (`В, К, М, Н, Т`), but completely omits their lowercase counterparts (`в, к, м, н, т`). When a user inputs lowercase Cyrillic characters, they are not mapped to Latin equivalents. In `scan()`, regexes fail to match. In `scan_despaced()`, `NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")` strips them as non-ASCII, fragmenting the target words and causing false negatives.
- **Fix**: Add all lowercase Cyrillic, Greek, and other common homoglyphs to `CONFUSABLES`.

### 4.5 Malware Tripwire Punctuation & Despacing Gap
- **Severity**: Medium
- **Location**: [`MALWARE_PATTERNS`] & [`DESPACED_PATTERNS`]
- **Mechanism**: All `MALWARE_PATTERNS` require word boundaries and whitespace (`\s*` or `\s+`), e.g., `r"\b(reverse|bind)\s*shell\b"`. If punctuation or symbols separate keywords (e.g., hyphens, slashes, or periods), the regex fails. Furthermore, `DESPACED_PATTERNS` only includes sentinel and CSAM patterns; malware patterns and admin `extra_patterns` are never scanned by `scan_despaced`.
- **Fix**: Allow non-alphanumeric separators in malware regexes or incorporate normalized keyword roots into `DESPACED_PATTERNS`.

---

## 5. Classifier Chunking & Architecture

### 5.1 Per-Request Semaphore Fails to Bound Concurrency
- **Severity**: High
- **Location**: [`_classify_chunks`]
- **Mechanism**: Line 403 creates the semaphore locally:
  ```python
  sem = asyncio.Semaphore(int(POLICY.guard.get("concurrency", 2)))
  ```
  This limits concurrency among chunks *within a single request*, but does not limit concurrency across concurrent requests. If 20 concurrent requests arrive, 40 parallel calls are dispatched to Ollama. Ollama instances with limited parallelism saturate quickly, causing queue backups, timeouts, and cascading `GuardUnavailable` (503) refusals.
- **Fix**: Make `sem` a module-level or `Policy`-level singleton shared across all requests.

### 5.2 User Context Truncation in Output Classification
- **Severity**: High
- **Location**: [`classify_output`]
- **Mechanism**: Line 430 extracts context using `user_ctx = request_text[-n:]` under the assumption that *"the instruction is usually at the end of a long prompt"*. If an attacker places their disallowed prompt at the beginning or middle of the request and pads the end with several thousand characters of innocuous text, the instruction is truncated. Llama Guard evaluates the assistant output against benign context, leading to a false negative.
- **Fix**: Retain the user instruction turn explicitly from `messages` rather than blindly slicing the tail of the concatenated request string.

### 5.3 Lack of Short-Circuiting in Chunk Evaluation
- **Severity**: Medium
- **Location**: [`_classify_chunks`]
- **Mechanism**: `await asyncio.gather(...)` executes all chunks to completion. If chunk 0 is unsafe, the system still awaits and processes up to 99 additional chunk calls against Ollama. This wastes substantial GPU/CPU resources and prolongs request latency.
- **Fix**: Use `asyncio.as_completed` to inspect results as they arrive and cancel remaining chunk tasks upon the first blocked verdict.

### 5.4 High Connection Churn
- **Severity**: Low
- **Location**: [`_guard_call`]
- **Mechanism**: Every chunk classification creates and destroys a separate `httpx.AsyncClient()` instance. Under heavy load, this causes socket exhaustion and adds TLS/TCP handshake latency.
- **Fix**: Maintain a persistent `httpx.AsyncClient` pool at module or class level.

---

## 6. Policy Reload & ReDoS Defense

### 6.1 Worker Thread Starvation via Uncancellable ReDoS Execution
- **Severity**: Critical
- **Location**: [`tripwires`]
- **Mechanism**: Line 320 dispatches regex execution to Python's default thread pool:
  ```python
  await asyncio.wait_for(asyncio.to_thread(tripwire_check, texts, lists), timeout=SCAN_BUDGET_S)
  ```
  While `asyncio.wait_for` raises `TimeoutError` on the event loop after 5 seconds, the underlying worker thread running `tripwire_check` **cannot be preempted or cancelled**. The thread continues executing the backtracking regex. Python's default `ThreadPoolExecutor` has a bounded worker count (typically $32$ threads). An attacker sending a small burst of requests triggering catastrophic backtracking will permanently occupy all worker threads, causing all subsequent threadpool tasks across LiteLLM to hang and fail.
- **Fix**: Use linear-time regular expression engines (e.g., Google `re2` via `google-re2` / `pyre2`) for user- or admin-supplied patterns, or execute regex evaluations in dedicated disposable subprocesses.

### 6.2 Policy Reset to Defaults on Stat Failures
- **Severity**: High
- **Location**: [`Policy.reload`]
- **Mechanism**: If `os.stat(POLICY_PATH)` raises `OSError` (e.g., transient file unlinking during atomic file replacement by the hub), line 109 sets `m = None`. Line 112 initializes `data = copy.deepcopy(DEFAULT_POLICY)`. Because `m is not None` is False, the `try/except` block reading the file is skipped, and line 135 overwrites `self.data` with `DEFAULT_POLICY`. Any custom categories, thresholds, and extra tripwires are wiped, violating the guarantee to *"keep the last good policy on a bad read"*.
- **Fix**: Return immediately when `os.stat` raises `OSError`:
  ```python
  except OSError as e:
      log.error("policy stat failed (%s); keeping previous policy", e)
      return
  ```

### 6.3 Event Loop Freeze & Ineffective ReDoS Probe in Policy Load
- **Severity**: Medium
- **Location**: [`_pathological`] & [`Policy.reload`]
- **Mechanism**: 
  1. `_pathological` tests patterns against a single hardcoded string of `'a'` and `'x'` characters. Backtracking regexes that trigger on other character sets (e.g., digits, whitespace, or other letters) execute in microseconds against the probe and pass validation.
  2. `rx.search(probe)` executes synchronously inside `Policy.reload()` on the main event loop thread without a timeout. If a pattern matches the probe's characters with severe backtracking, the event loop blocks indefinitely at load time.
  3. If `extra_patterns` contains a non-string element, `re.compile` raises `TypeError`. Because `_pathological` only catches `re.error`, the uncaught `TypeError` crashes `reload()` and disrupts request handling.
- **Fix**: Validate regexes using static AST analysis for nested quantifiers or compile them with `re2`. Catch `Exception` in `_pathological`.

---

## 7. Audit Logging & System Degradation

### 7.1 Thread Bomb Denial of Service via Audit Writes
- **Severity**: High
- **Location**: [`audit`]
- **Mechanism**: Line 352 handles audit logging by spawning an unpooled OS thread for every audit event:
  ```python
  threading.Thread(target=_audit_write, args=(rec,), daemon=True).start()
  ```
  An attacker sending thousands of requests that trigger policy vetos causes the process to spawn thousands of concurrent OS threads, leading to `RuntimeError: can't start new thread`, memory exhaustion, and process crashes.
- **Fix**: Use an asynchronous queue (`asyncio.Queue`) drained by a single background worker task, or a bounded thread pool.

### 7.2 Audit File Race Conditions & Log Corruption
- **Severity**: Medium
- **Location**: [`_audit_write`]
- **Mechanism**: Multiple audit threads run `_audit_write` concurrently without locking. When the file reaches `AUDIT_ROTATE_BYTES`, multiple threads concurrently attempt `os.replace(AUDIT_PATH, AUDIT_PATH + "." + timestamp)` with identical timestamps. Furthermore, unbuffered/unlocked concurrent appends can interleave JSON lines, corrupting the log file.
- **Fix**: Protect audit writing and rotation with a threading lock (`threading.Lock()`) or use Python's standard `logging.handlers.RotatingFileHandler`.

### 7.3 Streaming Hook Parameter Swapping Breaks Key Attribution
- **Severity**: Medium
- **Location**: [`async_post_call_streaming_iterator_hook`]
- **Mechanism**: In LiteLLM's `CustomLogger`, post-call hooks pass arguments positionally as `(data, response, user_api_key_dict)`. In `VetoGuard`, the signature is defined as `(self, user_api_key_dict, response, request_data: dict)`. Consequently, `user_api_key_dict` receives `data`, and `request_data` receives `user_api_key_dict`. When `_key_alias(user_api_key_dict)` runs in `audit()`, it looks for key fields inside the request `data` dict, resulting in `key_alias` consistently logging as `None` for streaming events.
- **Fix**: Standardize hook signatures to align with LiteLLM's positional parameter order:
  ```python
  async def async_post_call_streaming_iterator_hook(self, data, response, user_api_key_dict)
  ```

---

## Summary of Findings by Severity

| Severity | Count | Primary Impact |
| :--- | :---: | :--- |
| **Critical** | 5 | Safety bypass (multi-turn omission, empty text fail-open, dict response fail-open, multi-choice stream bypass, base64 classifier bypass) and service-wide ReDoS DoS |
| **High** | 6 | Thread bomb DoS, output classifier context truncation, uninspected reasoning tokens, streaming crash on empty choices, policy reset on stat error, Ollama saturation |
| **Medium** | 7 | Tool argument JSON escaping, confusable gaps, malware despacing gaps, ReDoS probe flaws, schema depth limits, audit file race conditions, stream hook attribution mismatch |
| **Low** | 1 | High HTTP connection churn in guard calls |
