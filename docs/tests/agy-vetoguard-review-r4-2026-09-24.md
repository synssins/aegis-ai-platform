# Agy (Gemini) adversarial review, round 4 — VetoGuard 2.5 — 2026-09-24

Permission-gated print mode (JSON output), read-only. Paths sanitised.

This defensive security review analyzes [`veto_filter.py`] (revision 2.5). 

Several weaknesses remain or were newly introduced in revision 2.5 that allow safety filter bypasses (fail-open), classifier degradation (false negatives), and runtime errors. **The remaining issues include High-severity bypasses and are not limited to Low/Medium.**

---

### 1. Fail-Open Request Classifier Bypass via Trailing Empty Turn

- **Severity**: High
- **Title**: Trailing Empty User Message Completely Suppresses Classifier Evaluation
- **Mechanism**:
  In [`RequestView`]:
  ```python
  last_user_idx = max((i for i, m in enumerate(msgs) if m.get("role") == "user"), default=0)
  self.new_segment = [t for t in (_content_to_text(m.get("content")) for m in msgs[last_user_idx:]) if t]
  ```
  And in [`classify_request`]:
  ```python
  chunks = _chunks("\n".join(view.new_texts))
  calls = [[{"role": "user", "content": ch}] for ch in chunks if ch.strip()]
  w = _window(view.turns)
  if w and w[-1]["role"] == "user" and len(w) > 1:
      calls.append(w)
  return await _classify_many(calls)
  ```
  If an attacker sends a multi-turn chat containing a disallowed prompt in turn $0$ followed by a dummy turn with `role: "user"` and empty content (`content: ""` or whitespace):
  1. `last_user_idx` resolves to the final dummy turn index.
  2. `self.new_segment` evaluates only `msgs[last_user_idx:]`, which yields `[]`. As a result, `view.new_texts` is empty.
  3. `chunks = _chunks("")` generates no non-empty chunks, so `calls` starts empty (`[]`).
  4. In `RequestView`, `if t:` drops empty content, meaning the dummy message is never appended to `self.turns`. `self.turns` contains only turn $0$ (`len(w) == 1`).
  5. The multi-turn condition `len(w) > 1` evaluates to `False`, so `w` is not appended to `calls`.
  6. `calls` remains completely empty (`[]`). [`_classify_many`] receives no tasks, immediately returning `False, []` (safe).
  7. Llama Guard is never invoked, failing open and forwarding the disallowed payload to the model.
- **Fix**: In [`RequestView`], determine `last_user_idx` by searching backwards for the last user turn that carries non-empty scannable content, or ensure that if `calls` is empty while `view.has_payload` is true, the request fails closed.

---

### 2. Streamed Reasoning Token Fragmentation Blinds Tripwires and Degrades Llama Guard

- **Severity**: High
- **Title**: Unjoined Streaming Reasoning Deltas Cause Lexical Evasion and Newline Token Injection
- **Mechanism**:
  In [`async_post_call_streaming_iterator_hook`]:
  ```python
  # Line 685: deltas appended as individual pieces
  slot["reason"].append(_content_to_text(v))
  ...
  # Lines 704-705: text is joined, but reason is extended as raw fragments
  outputs.append("".join(slot["text"]))
  outputs.extend(slot["reason"])
  ```
  `slot["text"]` is concatenated into a single string via `"".join(...)`, but `slot["reason"]` is extended as a list of raw delta fragments (often 1–3 characters each).
  When `outputs` is passed to [`_check_output`]:
  1. [`tripwires`] scans each item in `outputs` independently. Multi-character patterns (malware, sentinel, CSAM) never match across fragmented tokens.
  2. Base64 extraction ignores runs under 16 characters, failing to detect base64 encoded across deltas.
  3. In [`classify_output`], `text = "\n".join(o for o in outputs if o and o.strip())`. This injects a newline between every streamed token/syllable of the model's reasoning output, breaking word boundaries, corrupting semantic structure, and blinding Llama Guard.
- **Fix**: In [`async_post_call_streaming_iterator_hook`], concatenate reasoning deltas before output aggregation: `outputs.append("".join(slot["reason"]))`.

---

### 3. Streaming Hook Parameter Signature and Naming Mismatch

- **Severity**: High
- **Title**: Inverted Parameter Order and Non-Standard Keyword Name Crash Streaming Post-Call Hook
- **Mechanism**:
  Line 666 declares:
  ```python
  async def async_post_call_streaming_iterator_hook(self, user_api_key_dict, response, request_data: dict) -> AsyncGenerator:
  ```
  LiteLLM's `CustomLogger` base hook specifies `(self, data: dict, response: Any, user_api_key_dict: dict)`.
  - If LiteLLM invokes keyword arguments (`data=...`, `response=...`, `user_api_key_dict=...`), Python raises `TypeError` because the parameter is named `request_data` rather than `data`.
  - If LiteLLM invokes positional arguments `(data, response, user_api_key_dict)`, `request_data` receives the `user_api_key_dict` authentication object.
  At line 711, `_check_output` passes `request_data` to [`RequestView`]:
  `msgs = [m for m in (data.get("messages") or []) ...]`
  Because `data` is an authentication object without a `.get()` method, it raises an unhandled `AttributeError`, causing the async generator to abort.
- **Fix**: Align the signature with LiteLLM's convention (`self, data: dict, response: Any, user_api_key_dict: Any`), or use defensive argument normalization:
  ```python
  async def async_post_call_streaming_iterator_hook(self, *args, **kwargs) -> AsyncGenerator:
  ```

---

### 4. Base64 Multi-line Detection Gap and Zero-Width Character Blinding

- **Severity**: High
- **Title**: Two-Line Base64 Wrap Bypass and Control-Character Discard Vulnerability
- **Mechanism**:
  In [`_decoded_b64_fragments`]:
  1. `B64_BLOCK_RE` uses `(?:[A-Za-z0-9+/_-]{4,}={0,2}[ \t]*\r?\n){2,}[A-Za-z0-9+/_-]{4,}={0,2}`. The `{2,}` quantifier requires at least two newline characters (minimum of three lines). If an encoded payload is wrapped across exactly two lines (one newline), `B64_BLOCK_RE` will not match. When split at non-multiple-of-4 boundaries, individual line matching with `validate=True` fails, leaving the payload undecoded.
  2. Line 249 validates decoded strings:
     ```python
     if dec.strip() and all(ch.isprintable() or ch in "\n\t\r" for ch in dec):
     ```
     Python's `str.isprintable()` returns `False` for Unicode format characters (category `Cf`), such as zero-width space (`\u200b`), zero-width joiner (`\u200d`), or byte-order mark (`\ufeff`), as well as null bytes (`\x00`). If an attacker embeds a single zero-width character within an encoded payload, `all(...)` evaluates to `False`, and the entire decoded payload is discarded. Downstream language models ignore or strip zero-width characters, allowing the payload to execute uninspected.
- **Fix**:
  1. Update `B64_BLOCK_RE` to match two or more lines by changing the quantifier from `{2,}` to `{1,}`.
  2. Strip non-printable and zero-width format characters prior to safety evaluation rather than discarding the entire decoded candidate string.

---

### 5. Omission of Tool Calls from `new_segment` Bypasses Request Classifier

- **Severity**: High
- **Title**: Fabricated Tool Calls in Recent Turns Omitted from Request Chunk Classification
- **Mechanism**:
  In [`RequestView`]:
  ```python
  for m in msgs:
      t = _content_to_text(m.get("content"))
      if m.get("tool_calls"):
          t = (t + "\n" + _tool_calls_text(m.get("tool_calls"))).strip()
      if t:
          texts.append(t)
  ...
  self.new_segment = [t for t in (_content_to_text(m.get("content")) for m in msgs[last_user_idx:]) if t]
  ```
  `texts` (scanned by regex tripwires) incorporates `_tool_calls_text(m.get("tool_calls"))`, but `self.new_segment` strictly inspects `_content_to_text(m.get("content"))`.
  Because [`classify_request`] feeds `view.new_texts` (derived from `new_segment`) into Llama Guard chunks, any disallowed arguments inside `tool_calls` in the latest turn segment never reach the chunk classifier.
  Furthermore, if the latest message is an assistant turn containing `tool_calls`, `w[-1]["role"] == "user"` is `False`, skipping `_window` evaluation as well.
- **Fix**: In [`RequestView`], extract both content and tool calls when building `self.new_segment`.

---

### 6. Unhandled `SchemaBudgetExceeded` in Post-Call and Streaming Iterator

- **Severity**: Medium
- **Title**: Unhandled Schema Budget Exceptions Cause Uncontrolled 500 Failures in Post-Call Paths
- **Mechanism**:
  Revision 2.5 introduced [`SchemaBudgetExceeded`] for JSON objects exceeding recursion depth 24 or 5,000 nodes. While handled in `async_pre_call_hook`, it is unhandled in post-call routines:
  1. In [`async_post_call_streaming_iterator_hook`]:
     ```python
     outputs.extend(f"{n} {_unescape_json_string(a)}" for n, a in slot["tools"].values())
     ```
     This call occurs outside any `try...except` block. Deeply nested tool arguments raise `SchemaBudgetExceeded` and crash the generator.
  2. In [`_check_output`]:
     `classify_output(RequestView(data).last_user, outputs)`
     If `data` contains a tool/function schema exceeding the budget, `RequestView` raises `SchemaBudgetExceeded`. `_check_output` only catches `GuardUnavailable`, allowing the exception to propagate out of `async_post_call_success_hook`.
- **Fix**: Wrap post-call extraction and `_check_output` in `try...except SchemaBudgetExceeded` blocks and withhold the response fail-closed.

---

### 7. Character Normalisation Flaws (Greek Mu, Missing Omega, and Delimited Custom Patterns)

- **Severity**: Medium
- **Title**: Confusable Table Errors and Incomplete Despaced Scanning Allow Lexical Evasion
- **Mechanism**:
  1. In [`CONFUSABLES`], Greek lowercase mu (`"μ"`) is mapped to Latin `"u"` (`"μ": "u"`). Substituting `"μ"` into trigger words (e.g. replacing 'm' with 'μ') normalises to `'u'` instead of `'m'`, evading both [`MALWARE_PATTERNS`] and [`DESPACED_PATTERNS`].
  2. Greek lowercase omega (`"ω"`, visual homoglyph for Latin 'w') is missing from `CONFUSABLES`. When used in a word, [`normalise`] leaves it untouched, evading regex word boundaries. In [`scan_despaced`], `NON_ALNUM_RE` (`[^a-z0-9]+`) strips `"ω"`, corrupting the root word and bypassing despaced patterns.
  3. In [`tripwire_check`], `POLICY.extra_re` (admin tripwires) is checked only in `scan()`, never in `scan_despaced()`. Punctuation or delimiter interleaving inside admin keywords evades custom policy patterns entirely.
- **Fix**: Correct `"μ": "m"` and add `"ω": "w"` to `CONFUSABLES`. Include admin patterns in `scan_despaced` after stripping delimiters from regex literals.

---

### 8. Incomplete Multipart Block Extraction for Tool Use Payloads

- **Severity**: Medium
- **Title**: Multipart Request Blocks with Non-Text Keys Evade Extraction
- **Mechanism**:
  In [`_content_to_text`]:
  ```python
  elif isinstance(p, dict):
      for k in ("text", "input_text", "content", "refusal"):
          v = p.get(k)
          ...
  ```
  When content is supplied as a list of parts, dictionary blocks are inspected only for the four hardcoded keys. In multipart structures such as Anthropic `tool_use` blocks (`{"type": "tool_use", "name": "...", "input": {...}}`), the arguments reside under `"input"`. If accompanied by any other message providing text, `view.has_payload` passes, yet the embedded tool inputs are completely omitted from extraction, evading tripwires and the classifier.
- **Fix**: In [`_content_to_text`], traverse all values of unknown dictionary blocks recursively (e.g. using `_string_leaves`) instead of restricting inspection to four fixed keys.

---

### 9. Audit Logging Failure on Relative Path Configuration

- **Severity**: Low
- **Title**: `os.makedirs` Failure on Empty Directory Path Suppresses All Audit File Writes
- **Mechanism**:
  In [`_audit_writer`]:
  ```python
  os.makedirs(os.path.dirname(AUDIT_PATH), exist_ok=True)
  ```
  If `VETO_AUDIT_PATH` is configured as a relative filename without a directory component (e.g. `"veto-audit.jsonl"`), `os.path.dirname(AUDIT_PATH)` returns `""`. In Python, `os.makedirs("", exist_ok=True)` raises `FileNotFoundError: [Errno 2] No such file or directory: ''`. Every queued audit write fails at this statement, preventing the audit log file from ever being written.
- **Fix**: Guard directory creation:
  ```python
  if dir_name := os.path.dirname(AUDIT_PATH):
      os.makedirs(dir_name, exist_ok=True)
  ```

---

### 10. Middle-Truncation in `_headtail` Discards Sandwiched Context

- **Severity**: Low
- **Title**: Head-and-Tail Slicing Leaves Padding Sandwiches Invisible in Output Classification Context
- **Mechanism**:
  In [`_headtail`], strings exceeding $N$ characters (default 6,000) are truncated to the first $N/2$ and last $N/2$ characters, excising the middle.
  In [`classify_output`], `ctx = _headtail(user_turn or "", n)`. Unlike output chunks, `user_turn` is not partitioned with a sliding window. If an attacker pads a user turn with 3,500 characters of benign content at the beginning and end, placing malicious framing in the middle, `_headtail` strips the middle payload entirely. Llama Guard evaluates the assistant output against only the benign head and tail framing, missing context-dependent violations.
- **Fix**: In [`classify_output`], if `user_turn` exceeds chunk limits, evaluate candidate outputs across multiple chunked slices of the user context rather than excising the middle.
