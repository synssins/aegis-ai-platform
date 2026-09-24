# Agy (Gemini) adversarial review, round 3 — VetoGuard 2.4 — 2026-09-24

Permission-gated print mode (JSON output), read-only. Paths sanitised.

A defensive security code review of [`veto_filter.py`] (revision 2.4) follows below.

---

### 1. Request Field Coverage & Hook Parameter Inversion (Post-Call Fail-Open)

- **Severity**: Critical
- **Title**: Argument Inversion and Incomplete Resolution in [`_args_of`] Causes Post-Call Inspection to Completely Fail Open
- **Mechanism**: 
  Revision 2.4 introduced [`_args_of`] to handle LiteLLM passing `(key_dict, response, request_data)`. However, in [`async_post_call_success_hook`]:
  ```python
  data, user_api_key_dict = _args_of(data, response, user_api_key_dict)[0], user_api_key_dict
  ```
  When LiteLLM delivers `(key_dict, response, request_data)`:
  1. Parameter `data` receives `key_dict`.
  2. Parameter `user_api_key_dict` receives `response`.
  3. Parameter `response` receives `request_data`.
  
  Inside [`_args_of(data, response, key)`], only the 1st parameter (`data`) and 3rd parameter (`key`) are inspected for `"messages"` / `"prompt"` / `"model"`. The 2nd parameter (`response` = `request_data`) is never checked. `_args_of` falls through to line 562 returning `(data, key)` (`key_dict, response`).
  
  Line 616 assigns `data = key_dict`. Crucially, local variable `response` is never re-assigned and remains bound to `request_data`. Next:
  - Line 618 executes `extract_outputs(response)` on `request_data`, which has no `choices`, returning an empty list `[]`.
  - Line 622 checks `if (_g(response, "choices", None) or []) and not outputs:`. Because `request_data` has no `choices`, this check evaluates to `False`.
  - Line 625 calls `_check_output(..., outputs=[])`, which exits immediately at line 598 returning `None`.
  - Line 630 returns `response`.
  
  The generated response is never extracted, never checked against tripwires, and never classified, completely bypassing post-call safety.
- **Fix**: Inspect all three arguments dynamically in [`_args_of`] to identify which object is the `ModelResponse` (e.g. checking for `choices`), which is `request_data` (dict with `messages` or `model`), and which is `key_dict`. Reassign `data, response, user_api_key_dict` consistently before calling [`extract_outputs`].

---

### 2. Request Field Coverage & Classifier Chunking

- **Severity**: High
- **Title**: Top-Level `system`, `tools`, and Function Schemas Excluded from Classifier Scanning
- **Mechanism**: 
  In [`RequestView`]:
  - Top-level `data.get("system")` (line 321) and `data.get("tools")` / `data.get("functions")` (line 331) are appended to `texts`, but NOT to `self.new_segment`.
  - [`self.turns`] only processes messages inside `data.get("messages")`, completely omitting top-level `system` and tool parameters.
  - In [`classify_request`], chunking runs strictly over `view.new_texts` (which is `new_segment + decoded`).
  
  As a result, top-level system prompts (standard in Anthropic and Bedrock APIs) and tool/function descriptions are only scanned by lexical regex tripwires. They are never chunked or submitted to Llama Guard, allowing prompt injection, jailbreaks, or policy-violating instructions embedded in system instructions or tool specifications to completely evade the semantic classifier.
- **Fix**: Append extracted strings from `data.get("system")`, `tools`, and `functions` into `self.new_segment`, and inject top-level system instructions at the start of `self.turns`.

---

### 3. Tool-Call Path & Traversal Recursion Cap

- **Severity**: High
- **Title**: Silent Dropping of JSON Keys and Deeply Nested Payloads (>24 Depth) Bypasses Safety Gates
- **Mechanism**: 
  1. **Key Dropping**: In [`_string_leaves`], line 260 only iterates over `obj.values()`. If an attacker embeds payloads in JSON keys (e.g. `{"<instruction>": "value"}` in tool-call arguments or schema property names), the keys are completely skipped.
  2. **Fail-Open on Depth/Node Limits**: When JSON object nesting exceeds depth 24 or `MAX_SCHEMA_NODES` is exhausted, line 255 silently returns `[]`. In [`_unescape_json_string`], this collapses to `""`. 
  
  An attacker can wrap a disallowed payload inside 25 levels of nested JSON dictionaries. Instead of failing closed, the filter silently drops the inner content, causing [`_tool_calls_text`] to extract only the tool name. The payload completely bypasses tripwires and classifier scanning.
- **Fix**: Traverse both `obj.keys()` and `obj.values()` in [`_string_leaves`]. If depth exceeds 24 or the node budget is exhausted, raise a `SchemaBudgetExceeded` error and refuse the request (fail-closed) rather than returning an empty string.

---

### 4. Normalisation Gaps: Despaced Lexical Evasion

- **Severity**: High
- **Title**: Unmapped Confusables and Punctuation Stripping Enable Complete Despaced Lexical Evasion
- **Mechanism**: 
  [`CONFUSABLES`] only maps a partial set of Cyrillic and Greek characters to Latin equivalents. For instance, Greek lowercase sigma (`σ` / `ς`) and Cyrillic `з` (ze) are absent.
  
  In [`normalise`], unmapped characters remain intact. However, in [`scan_despaced`]:
  ```python
  d = NON_ALNUM_RE.sub("", normalise(t))
  ```
  `NON_ALNUM_RE` is `[^a-z0-9]+` (line 203). It strips any character not in ASCII `[a-z0-9]`.
  
  If an attacker substitutes a Latin character with an unmapped confusable (e.g. replacing 's' with Greek `σ`), or intersperses non-alphanumeric punctuation inside a tripwire keyword, [`NON_ALNUM_RE`] strips the unmapped character out entirely rather than transliterating it. The target keyword collapses into a truncated string (e.g. missing letters), evading both primary regexes and despaced tripwires.
- **Fix**: Implement a standard Unicode confusable skeleton algorithm (e.g. Unicode TR39 skeleton normalization) prior to stripping, or treat unmapped non-ASCII characters as token delimiters rather than silently deleting them.

---

### 5. Normalisation Gaps: Base64 Decoding

- **Severity**: High
- **Title**: Base64 Detection Evaded via Whitespace, Line Wrapping, and Formatting Characters
- **Mechanism**: 
  In [`_decoded_b64_fragments`] and [`B64_RUN_RE`]:
  1. **Line Wraps and Formatting**: [`B64_RUN_RE`] matches contiguous runs of `{16,}` characters. Standard MIME/PEM base64 formatted with line wraps (`\r?\n`) or arbitrary spaces will either fail to match the 16-character minimum or break into unaligned fragments that fail UTF-8 decoding.
  2. **Non-Printable Character Invalidation**: Line 235 requires `all(ch.isprintable() or ch in "\n\t\r" for ch in dec)`. In Python, zero-width characters (e.g. `\u200b`, `\ufeff`) return `False` for `isprintable()`. An attacker who embeds a single zero-width space or null byte anywhere in the base64-encoded text causes `all(...)` to evaluate to `False`. The entire decoded fragment is dropped, leaving the payload completely hidden from both regex and classifier layers.
- **Fix**: Normalize and strip inner whitespace across suspected base64 sequences before decoding. Rather than dropping entire decoded strings upon finding unprintable characters, strip formatting marks and evaluate the clean printable residue.

---

### 6. Streaming Path: Thinking/Reasoning Leakage (NEW in 2.4)

- **Severity**: High
- **Title**: Disallowed Thinking/Reasoning Tokens Leaked to Client in Synthetic Withhold Chunk
- **Mechanism**: 
  When streaming output violates policy, lines 680–695 synthesize a withhold chunk by deep-copying the first chunk with choices:
  ```python
  first = copy.deepcopy(src)
  for ch in _g(first, "choices"):
      d = _g(ch, "delta", None)
      if d is not None:
          if isinstance(d, dict):
              d["content"], d["tool_calls"] = WITHHELD_MSG, None
          else:
              d.content, d.tool_calls = WITHHELD_MSG, None
  ```
  While `content` and `tool_calls` are overwritten, fields in [`REASONING_KEYS`] (`reasoning_content`, `reasoning`, `thinking`, `refusal`) are never cleared.
  
  In reasoning-oriented LLMs, early streaming chunks routinely contain `reasoning_content` or `thinking` blocks. Because `first` retains these keys, the client application receives the raw thinking content alongside the withhold notice, directly leaking disallowed generated reasoning.
- **Fix**: Explicitly clear or delete all keys listed in `REASONING_KEYS` on `delta` within the synthetic withhold chunk.

---

### 7. Streaming Path: Fail-Open on Unscannable Output

- **Severity**: Medium
- **Title**: Streaming Iterator Fails Open on Unscannable or Custom Deltas
- **Mechanism**: 
  In [`async_post_call_success_hook`], if choices exist but yield no scannable outputs, the filter fails closed (`_refuse(400, ...)`).
  
  In [`async_post_call_streaming_iterator_hook`], if an upstream provider streams delta structures using unrecognized field keys or custom structures, `outputs` in line 669 remains empty. Line 674 calls `_check_output`, which immediately returns `None` for empty outputs (line 598). `withheld` remains `None`. Lines 676–677 then yield every buffered chunk to the user without any safety verdict, failing open.
- **Fix**: Verify in the streaming hook that if `buffered` contained choices, `outputs` must contain scannable text; otherwise, mark `withheld = ["NO_SCANNABLE_OUTPUT"]` to fail closed.

---

### 8. Classifier Chunking & Multi-Turn Window (Exploit of Trade-off 1)

- **Severity**: Medium
- **Title**: Context Truncation Asymmetry Creates Blind Spots in Multi-Turn and Output Classifications
- **Mechanism**: 
  1. In [`_window`], multi-turn history turns are sliced by taking the tail: `t["content"][-n:]`.
  2. In [`classify_output`], output classification user context is sliced by taking the head: `(user_turn or "")[:n]`.
  
  If an adversary structures a multi-turn prompt where the harmful context resides at the beginning of a user turn exceeding 6,000 characters followed by benign filler, `_window` truncates the head away. Meanwhile, the single-turn chunk calls in `classify_request` evaluate the head in isolation without multi-turn history. Neither call sees the adversarial context.
  
  Similarly, for output classification, if the instruction that makes the model response disallowed was at the end of a long user turn, `[:n]` discards it, leaving Llama Guard evaluating the output against irrelevant preamble.
- **Fix**: Preserve prompt context by slicing around the interaction boundary or sampling head and tail windows, rather than performing unilateral hard truncations.

---

### 9. Policy Reload & Regex ReDoS (Exploit of Trade-off 2)

- **Severity**: High
- **Title**: Charset-Restricted ReDoS Timing Probe Allows Permanent Thread Pool Exhaustion
- **Mechanism**: 
  [`_pathological`] checks for nested quantifiers with a regex and executes probe inputs in line 97:
  ```python
  probes = [(ch * 60 + "!") * 3 + tail for ch in ("a", "1", " ", "x", "-") for tail in ("", "aaaaaaaaaaaaaaaaaaaaaaaaaab")]
  ```
  The timing probes test only five characters (`a`, `1`, space, `x`, `-`). Any pattern with catastrophic backtracking on another character (e.g. `(b|b+)+$` or overlapping digit classes on non-matching inputs) completes the probe in microseconds and is accepted into `POLICY.extra_re`.
  
  When evaluated on user input, line 369 executes `asyncio.to_thread(tripwire_check, texts, lists)`. While `asyncio.wait_for` raises an `asyncio.TimeoutError` at 5.0 seconds, Python's GIL/underlying OS worker thread executing `re.search` cannot be cancelled. The worker thread continues running at 100% CPU indefinitely. A small number of requests will exhaust the `asyncio` default threadpool, causing denial of service for all subsequent requests.
- **Fix**: Enforce strict pattern grammar constraints, compile regexes using a linear-time DFA engine, or execute regex searches in disposable worker sub-processes that can be forcibly killed upon timeout.

---

### 10. Error Handling & Concurrency: Event Loop Desynchronization

- **Severity**: High
- **Title**: `httpx.AsyncClient` Bound to Stale Event Loop Triggers 503 Guard Outages
- **Mechanism**: 
  In [`_client()`]:
  ```python
  if _CLIENT is None:
      _CLIENT = httpx.AsyncClient(...)
  ```
  `_CLIENT` is stored in a global variable and is never verified against the active event loop. In contrast, [`_sem()`] verifies `_SEM_LOOP is not loop`.
  
  When LiteLLM handles requests across multiple worker threads or new event loops, calling `_CLIENT.post()` across loop boundaries raises `RuntimeError: Task attached to different loop`. Line 457 catches this and raises `GuardUnavailable`, causing all subsequent requests on that loop to fail with 503 errors. Additionally, `_SEM` never refreshes when `concurrency` is updated in the policy file.
- **Fix**: Recreate or cache `httpx.AsyncClient` per running event loop (or use loop-local storage), and update `_SEM` whenever policy reload detects a concurrency configuration change.

---

### 11. Audit Logging: Unsynchronized Rotation and Data Leakage

- **Severity**: Medium
- **Title**: Unlocked Multi-Process Log Rotation and Reflection of User Content via Error Strings
- **Mechanism**: 
  1. **Log Corruption**: Docstring line 25 claims "locked rotation", but lines 385–390 execute `os.replace` without file locking. In multi-worker LiteLLM deployments (standard in production Uvicorn/Gunicorn), worker processes concurrently checking file size collide, clobbering rotated files and losing audit records.
  2. **Content Leakage**: Line 408 stores `detail[:200]`. In lines 588, 609, 620, and 661, `detail` is populated with `str(e)`. For extraction errors or JSON parsing errors (such as `json.decoder.JSONDecodeError`), `str(e)` includes snippets of unparsed payload text, violating the guarantee in line 30 that audit logs never record user content.
- **Fix**: Apply an advisory inter-process file lock (`fcntl.flock`) around the rotation check and log write in [`_audit_writer`]. Redact or sanitize `str(e)` in audit calls to output generic error descriptions.
