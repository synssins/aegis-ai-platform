"""
VetoGuard rev 2.3 — LiteLLM pre/post-call safety gate: lexical tripwire + Llama Guard classifier,
driven by an admin-editable policy file (hot-reloaded) that only the hub may write.

rev 2.3 addresses the Agy adversarial review of 2026-09-24 (docs/tests/agy-vetoguard-review-2026-09-24.md):
  1.1/1.2/4.2  scan everything the caller supplied in this request: the latest user turn AND every
               message after it (assistant prefill, tool results, tool_calls args), top-level `system`,
               `prompt`, `input`, and tool/function schema text. A request whose last message is not
               a user turn is no longer skipped.
  2.1/2.2/2.3  normalisation strips combining marks and Unicode format chars, maps common confusables,
               decodes standard + URL-safe base64 and feeds decoded text to the classifier too;
               despaced matching removes every non-alphanumeric.
  3.1/3.2/3.3/3.4  streaming: tool_calls deltas are classified, tripwires run on output, buffered
               output is capped, empty `choices` are tolerated, withholding never raises mid-stream.
  4.1          extraction failure is fail-closed.
  5.1/5.3      overlapping chunk windows; lower chunk budget; bounded concurrency.
  6.1/6.2/6.3  policy reload keeps the last good policy on a bad read; admin regexes are checked for
               pathological backtracking at load and every scan runs under a wall-clock budget
               (timeout => refuse); reload checks are rate-limited.
  7.1/7.2      verdict = exact first line; stream withholding emits a synthetic content_filter chunk.
  8.1/8.2      key attribution works for dict-shaped key info; audit writes are off the event loop and
               the log rotates at 50 MB.

Layers (all fail-closed): 1. lexical tripwire  2. Llama Guard classifier (pre + post, streaming buffered).
Policy file: VETO_POLICY_PATH (default /app/policy/veto-policy.json), written by the hub. S4 always blocked.
Audit: VETO_AUDIT_PATH — timestamps, stage, reason/category, call id, key alias, model. Never content.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import copy
import json
import logging
import os
import re
import threading
import time
import unicodedata
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Iterable

import httpx
from fastapi import HTTPException
from litellm.integrations.custom_logger import CustomLogger

log = logging.getLogger("vetoguard")

GUARD_URL = os.environ.get("VETO_GUARD_URL", "http://ollama:11434").rstrip("/")
POLICY_PATH = os.environ.get("VETO_POLICY_PATH", "/app/policy/veto-policy.json")
AUDIT_PATH = os.environ.get("VETO_AUDIT_PATH", "/app/audit/veto-audit.jsonl")
AUDIT_ROTATE_BYTES = 50 * 1024 * 1024
WITHHELD_MSG = "[Response withheld by policy: veto_triggered]"
SCAN_BUDGET_S = 5.0            # wall-clock budget for all regex work on one request (ReDoS guard)
MAX_OUTPUT_CHARS = 400_000     # buffered stream cap (~100k tokens); beyond => withheld
POLICY_CHECK_INTERVAL_S = 2.0

LLAMA_GUARD_CATEGORIES = {
    "S1": "Violent Crimes", "S2": "Non-Violent Crimes", "S3": "Sex-Related Crimes",
    "S4": "Child Sexual Exploitation", "S5": "Defamation", "S6": "Specialized Advice",
    "S7": "Privacy", "S8": "Intellectual Property", "S9": "Indiscriminate Weapons",
    "S10": "Hate", "S11": "Suicide & Self-Harm", "S12": "Sexual Content",
    "S13": "Elections", "S14": "Code Interpreter Abuse",
}
LOCKED_CATEGORIES = {"S4"}
DEFAULT_BLOCK = {"S1", "S2", "S3", "S4", "S9", "S10", "S11"}
DEFAULT_POLICY = {
    "guard": {"model": os.environ.get("VETO_GUARD_MODEL", "llama-guard3:1b"),
              "chunk_chars": 6000, "chunk_overlap": 600, "max_chunks": 100, "timeout": 60, "concurrency": 2},
    "categories": {c: {"block": c in DEFAULT_BLOCK} for c in LLAMA_GUARD_CATEGORIES},
    "tripwires": {"enabled": True, "extra_patterns": []},
}


# ---------------------------------------------------------------------------
# Policy (hot reload; keeps last good policy on failure; rate-limited stat)
# ---------------------------------------------------------------------------
def _pathological(pattern: str) -> bool:
    """Reject regexes that back-track catastrophically: probe with adversarial input under a budget."""
    try:
        rx = re.compile(pattern, re.IGNORECASE | re.DOTALL)
    except re.error:
        return True
    probe = ("a" * 40 + "!") * 3 + "x" * 400 + " " * 50 + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"
    t = time.perf_counter()
    rx.search(probe)
    return (time.perf_counter() - t) > 0.05


class Policy:
    def __init__(self):
        self._mtime = None
        self._last_check = 0.0
        self._lock = threading.Lock()
        self.data = copy.deepcopy(DEFAULT_POLICY)
        self.extra_re: list[re.Pattern] = []
        self.reload(force=True)

    def reload(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_check < POLICY_CHECK_INTERVAL_S:
            return
        with self._lock:
            self._last_check = now
            try:
                m = os.stat(POLICY_PATH).st_mtime
            except OSError:
                m = None
            if m == self._mtime and not force:
                return
            data = copy.deepcopy(DEFAULT_POLICY)
            if m is not None:
                try:
                    with open(POLICY_PATH, encoding="utf-8") as f:
                        loaded = json.load(f)
                    for k in ("guard", "tripwires"):
                        if isinstance(loaded.get(k), dict):
                            data[k].update(loaded[k])
                    if isinstance(loaded.get("categories"), dict):
                        for c, v in loaded["categories"].items():
                            if c in data["categories"] and isinstance(v, dict):
                                data["categories"][c]["block"] = bool(v.get("block", data["categories"][c]["block"]))
                except Exception as e:  # noqa: BLE001 — keep the last good policy, do not fall back to defaults
                    log.error("policy read failed (%s); keeping previous policy", e)
                    return
            for c in LOCKED_CATEGORIES:
                data["categories"][c]["block"] = True
            pats = []
            for p in data["tripwires"].get("extra_patterns", []):
                if _pathological(p):
                    log.error("ignoring pathological/invalid extra tripwire %r", p)
                    continue
                pats.append(re.compile(p, re.IGNORECASE | re.DOTALL))
            self.data, self.extra_re, self._mtime = data, pats, m
            log.warning("VetoGuard policy loaded: model=%s blocked=%s extra_tripwires=%d",
                        data["guard"]["model"], sorted(self.blocked()), len(pats))

    def blocked(self) -> set[str]:
        return {c for c, v in self.data["categories"].items() if v.get("block")} | LOCKED_CATEGORIES

    @property
    def guard(self) -> dict:
        return self.data["guard"]


POLICY = Policy()


# ---------------------------------------------------------------------------
# Lexical tripwire
# ---------------------------------------------------------------------------
SENTINEL_PATTERNS = [r"test[\s_]*sentinel[\s_]*block[\s_]*alpha"]
MALWARE_PATTERNS = [
    r"\b(reverse|bind)\s*shell\b",
    r"\b(keylogger|ransomware|rootkit|botnet|credential\s*stealer|info\s*stealer)\b",
    r"\bc2\s*(server|beacon|framework)\b",
    r"\b(bypass|evade|disable)\s+(the\s+)?(edr|antivirus|anti-virus|defender|amsi|security\s*controls?)\b",
    r"\b(write|create|build|make)\s+(me\s+)?(a\s+|some\s+)?(malware|a\s+virus|a\s+worm|a\s+trojan)\b",
]
CSAM_PATTERNS = [
    r"\b(child|children|underage|minor|minors|teen|teens|infant|toddler|preteen|kid|kids)\b"
    r".{0,60}?\b(porn|pornograph\w*|sex\w*|nude|naked|erotic\w*|explicit|molest\w*|abuse\w*)\b",
    r"\b(csam|csem|pedophil\w*|paedophil\w*|loli\w*|shota\w*)\b",
]
DESPACED_PATTERNS = [r"testsentinelblockalpha", r"csam", r"pedophil", r"paedophil"]

_FLAGS = re.IGNORECASE | re.DOTALL
SENTINEL_RE = [re.compile(p, _FLAGS) for p in SENTINEL_PATTERNS]
MALWARE_RE = [re.compile(p, _FLAGS) for p in MALWARE_PATTERNS]
CSAM_RE = [re.compile(p, _FLAGS) for p in CSAM_PATTERNS]
DESPACED_RE = [re.compile(p, _FLAGS) for p in DESPACED_PATTERNS]
OUTPUT_TRIPWIRES = ("sentinel", "csam", "extra")   # malware phrases legitimately appear in defensive answers

WS_RE = re.compile(r"\s+")
NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")
B64_RUN_RE = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")
MAX_SCAN_CHARS = 2_000_000
# Common cross-script confusables -> Latin (Cyrillic / Greek letters that render like ASCII)
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X", "У": "Y", "І": "I", "Ј": "J", "Ѕ": "S", "К": "K", "М": "M", "Н": "H", "Т": "T", "В": "B",
    "α": "a", "ο": "o", "ε": "e", "ι": "i", "ν": "v", "κ": "k", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
})


def normalise(text: str) -> str:
    text = text[:MAX_SCAN_CHARS]
    text = unicodedata.normalize("NFD", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) not in ("Mn", "Cf", "Cc") or ch in "\n\t")
    text = unicodedata.normalize("NFKC", text).translate(CONFUSABLES)
    return WS_RE.sub(" ", text).lower()


def _decoded_b64_fragments(text: str) -> list[str]:
    out = []
    for m in B64_RUN_RE.finditer(re.sub(r"[\r\n\t ]", "", text) if len(text) < 200_000 else text):
        s = m.group(0).replace("-", "+").replace("_", "/")
        s += "=" * (-len(s) % 4)
        try:
            dec = base64.b64decode(s, validate=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if dec.isprintable() or "\n" in dec:
            out.append(dec)
    return out


def _content_to_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            str(p.get("text", "")) if isinstance(p, dict) and p.get("type") == "text" else (p if isinstance(p, str) else "")
            for p in content
        )
    return str(content)


def _tool_calls_text(tcs: Any) -> str:
    parts = []
    for tc in tcs or []:
        fn = tc.get("function", {}) if isinstance(tc, dict) else getattr(tc, "function", None)
        name = fn.get("name", "") if isinstance(fn, dict) else getattr(fn, "name", "")
        args = fn.get("arguments", "") if isinstance(fn, dict) else getattr(fn, "arguments", "")
        parts.append(f"{name} {args}")
    return "\n".join(parts)


def _schema_text(obj: Any, depth: int = 0) -> str:
    """All string leaves of tool/function schemas (descriptions, enums, defaults)."""
    if depth > 8:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return "\n".join(_schema_text(v, depth + 1) for v in obj.values())
    if isinstance(obj, list):
        return "\n".join(_schema_text(v, depth + 1) for v in obj)
    return ""


def collect_request_text(data: dict) -> list[str]:
    """Everything the caller supplied that steers this request.

    Latest user turn and every message after it (assistant prefill, tool results, assistant tool_calls),
    top-level `system`, `prompt`, `input`, and tool/function schema text. If there is no user message
    at all, every message is scanned.
    """
    msgs = [m for m in (data.get("messages") or []) if isinstance(m, dict)]
    last_user = max((i for i, m in enumerate(msgs) if m.get("role") == "user"), default=None)
    scope = msgs[last_user:] if last_user is not None else msgs
    texts: list[str] = []
    for m in scope:
        texts.append(_content_to_text(m.get("content")))
        if m.get("tool_calls"):
            texts.append(_tool_calls_text(m.get("tool_calls")))
    # system prompts from the caller (OpenAI-style role or provider-style top-level key)
    for m in msgs:
        if m.get("role") in ("system", "developer") and m is not scope[0] if scope else True:
            texts.append(_content_to_text(m.get("content")))
    if data.get("system"):
        texts.append(_content_to_text(data.get("system")))
    for key in ("prompt", "input"):
        v = data.get(key)
        if isinstance(v, list):
            texts.extend(str(x) for x in v)
        elif v:
            texts.append(str(v))
    for key in ("tools", "functions"):
        if data.get(key):
            texts.append(_schema_text(data.get(key)))
    return [t for t in texts if t and t.strip()]


def _candidates(t: str) -> list[str]:
    n = normalise(t)
    return [n, *(normalise(f) for f in _decoded_b64_fragments(t))]


def scan(texts: Iterable[str], patterns: list[re.Pattern]) -> str | None:
    if not patterns:
        return None
    for t in texts:
        for c in _candidates(t):
            for p in patterns:
                if p.search(c):
                    return p.pattern
    return None


def scan_despaced(texts: Iterable[str]) -> str | None:
    for t in texts:
        for c in _candidates(t):
            d = NON_ALNUM_RE.sub("", c)
            for p in DESPACED_RE:
                if p.search(d):
                    return p.pattern
    return None


def tripwire_check(texts: list[str], lists: tuple[str, ...]) -> tuple[str, str] | None:
    """Run the named tripwire lists; returns (list_name, pattern) on first hit. Synchronous; run under a budget."""
    table = {"sentinel": SENTINEL_RE, "csam": CSAM_RE, "malware": MALWARE_RE, "extra": POLICY.extra_re}
    for name in lists:
        hit = scan(texts, table[name])
        if hit:
            return name, hit
    hit = scan_despaced(texts)
    if hit:
        return "despaced", hit
    return None


async def tripwires(texts: list[str], lists: tuple[str, ...]) -> tuple[str, str] | None | str:
    """Returns hit tuple, None, or the string 'timeout' if the regex budget was exhausted (ReDoS guard)."""
    try:
        return await asyncio.wait_for(asyncio.to_thread(tripwire_check, texts, lists), timeout=SCAN_BUDGET_S)
    except asyncio.TimeoutError:
        return "timeout"


# ---------------------------------------------------------------------------
# Audit (off the event loop; rotates)
# ---------------------------------------------------------------------------
def _key_alias(key_dict: Any) -> str | None:
    if isinstance(key_dict, dict):
        return key_dict.get("key_alias") or key_dict.get("user_id")
    return getattr(key_dict, "key_alias", None) or getattr(key_dict, "user_id", None)


def _audit_write(rec: dict) -> None:
    try:
        os.makedirs(os.path.dirname(AUDIT_PATH), exist_ok=True)
        try:
            if os.path.getsize(AUDIT_PATH) > AUDIT_ROTATE_BYTES:
                os.replace(AUDIT_PATH, AUDIT_PATH + "." + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
        except OSError:
            pass
        with open(AUDIT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError as e:
        log.error("audit write failed: %s", e)


def audit(stage: str, reason: str, detail: str, data: dict, key_dict: Any) -> None:
    rec = {"ts": datetime.now(timezone.utc).isoformat(), "stage": stage, "reason": reason, "detail": detail[:200],
           "call_id": data.get("litellm_call_id"), "model": data.get("model"), "key_alias": _key_alias(key_dict)}
    log.warning("VETO %s", json.dumps(rec))
    threading.Thread(target=_audit_write, args=(rec,), daemon=True).start()


def _refuse(status: int, code: str, message: str) -> None:
    raise HTTPException(status_code=status, detail={"error": {"code": code, "type": "invalid_request_error", "message": message}})


# ---------------------------------------------------------------------------
# Classifier (Llama Guard via Ollama)
# ---------------------------------------------------------------------------
class GuardUnavailable(Exception):
    pass


async def _guard_call(messages: list[dict]) -> tuple[bool, list[str]]:
    g = POLICY.guard
    payload = {"model": g["model"], "messages": messages, "stream": False,
               "options": {"temperature": 0, "num_predict": 32, "num_ctx": 8192}}
    try:
        async with httpx.AsyncClient(timeout=float(g.get("timeout", 60))) as client:
            r = await client.post(f"{GUARD_URL}/api/chat", json=payload)
            r.raise_for_status()
            verdict = (r.json().get("message", {}).get("content") or "").strip().lower()
    except Exception as e:  # noqa: BLE001
        raise GuardUnavailable(str(e)) from e
    lines = [l.strip() for l in verdict.splitlines() if l.strip()]
    if not lines:
        raise GuardUnavailable("empty verdict")
    if lines[0] == "safe":
        return False, []
    if lines[0] == "unsafe":
        cats = [c.upper() for c in re.findall(r"s\d{1,2}", " ".join(lines[1:]))]
        return True, cats or ["UNSPECIFIED"]
    # Anything else is not a verdict; treat as unsafe/unspecified (fail-closed) and log the shape.
    log.error("unexpected guard verdict shape: %r", verdict[:80])
    return True, ["UNPARSEABLE_VERDICT"]


def _chunks(text: str) -> list[str]:
    g = POLICY.guard
    n, ov = int(g.get("chunk_chars", 6000)), int(g.get("chunk_overlap", 600))
    step = max(n - ov, n // 2)
    return [text[i:i + n] for i in range(0, max(len(text), 1), step)] or [""]


def _blocked_subset(cats: list[str]) -> list[str]:
    blocked = POLICY.blocked()
    return [c for c in cats if c in blocked or c in ("UNSPECIFIED", "UNPARSEABLE_VERDICT")]


async def _classify_chunks(build: Any, chunks: list[str]) -> tuple[bool, list[str]]:
    sem = asyncio.Semaphore(int(POLICY.guard.get("concurrency", 2)))

    async def one(ch: str):
        async with sem:
            return await _guard_call(build(ch))

    results = await asyncio.gather(*(one(ch) for ch in chunks if ch.strip()))
    for unsafe, cats in results:
        if unsafe and (b := _blocked_subset(cats)):
            return True, b
    return False, []


async def classify_request(texts: list[str]) -> tuple[bool, list[str]]:
    chunks = _chunks("\n".join(texts))
    if len(chunks) > int(POLICY.guard.get("max_chunks", 100)):
        _refuse(413, "prompt_too_long_for_guard", "Input exceeds the classifier budget.")
    return await _classify_chunks(lambda ch: [{"role": "user", "content": ch}], chunks)


async def classify_output(request_text: str, output: str) -> tuple[bool, list[str]]:
    if not output.strip():
        return False, []
    chunks = _chunks(output)
    if len(chunks) > int(POLICY.guard.get("max_chunks", 100)):
        return True, ["OUTPUT_TOO_LONG_FOR_GUARD"]
    n = int(POLICY.guard.get("chunk_chars", 6000))
    user_ctx = request_text[-n:]   # the instruction is usually at the end of a long prompt
    return await _classify_chunks(lambda ch: [{"role": "user", "content": user_ctx}, {"role": "assistant", "content": ch}], chunks)


# ---------------------------------------------------------------------------
# LiteLLM hooks
# ---------------------------------------------------------------------------
class VetoGuard(CustomLogger):
    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        POLICY.reload()
        texts = collect_request_text(data)
        if not texts:
            return data
        if POLICY.data["tripwires"].get("enabled", True):
            hit = await tripwires(texts, ("sentinel", "csam", "malware", "extra"))
            if hit == "timeout":
                audit("pre_call", "regex_budget_exhausted", "", data, user_api_key_dict)
                _refuse(400, "veto_triggered", "Request refused by policy.")
            if hit:
                audit("pre_call", f"regex:{hit[0]}", hit[1], data, user_api_key_dict)
                _refuse(400, "veto_triggered", "Request refused by policy.")
        try:
            unsafe, cats = await classify_request(texts)
        except GuardUnavailable as e:
            audit("pre_call", "guard_unavailable", str(e), data, user_api_key_dict)
            _refuse(503, "guard_unavailable", "Safety classifier unavailable; request refused (fail-closed).")
        if unsafe:
            audit("pre_call", "classifier", ",".join(cats), data, user_api_key_dict)
            _refuse(400, "veto_triggered", "Request refused by policy.")
        return data

    async def _check_output(self, stage: str, data: dict, key: Any, outputs: list[str]) -> list[str] | None:
        """Returns None if the output may be released, else the reason list (never raises for policy hits)."""
        if POLICY.data["tripwires"].get("enabled", True):
            hit = await tripwires(outputs, OUTPUT_TRIPWIRES)
            if hit == "timeout":
                audit(stage, "regex_budget_exhausted", "", data, key); return ["REGEX_BUDGET"]
            if hit:
                audit(stage, f"regex:{hit[0]}", hit[1], data, key); return [hit[0]]
        req_text = "\n".join(collect_request_text(data))
        try:
            unsafe, cats = await classify_output(req_text, "\n".join(outputs))
        except GuardUnavailable as e:
            audit(stage, "guard_unavailable", str(e), data, key); return ["GUARD_UNAVAILABLE"]
        if unsafe:
            audit(stage, "classifier", ",".join(cats), data, key); return cats
        return None

    async def async_post_call_success_hook(self, data, user_api_key_dict, response):
        POLICY.reload()
        try:
            outputs = []
            for c in getattr(response, "choices", []) or []:
                msg = getattr(c, "message", None)
                outputs.append(_content_to_text(getattr(msg, "content", None)))
                outputs.append(_tool_calls_text(getattr(msg, "tool_calls", None)))
        except Exception as e:  # noqa: BLE001 — fail closed
            audit("post_call", "extraction_failure", str(e), data, user_api_key_dict)
            _refuse(500, "safety_processing_error", "Response could not be evaluated; withheld (fail-closed).")
        reasons = await self._check_output("post_call", data, user_api_key_dict, [o for o in outputs if o])
        if reasons:
            if "GUARD_UNAVAILABLE" in reasons:
                _refuse(503, "guard_unavailable", "Safety classifier unavailable; response withheld (fail-closed).")
            _refuse(400, "veto_triggered", "Response withheld by policy.")
        return response

    async def async_post_call_streaming_iterator_hook(self, user_api_key_dict, response, request_data: dict) -> AsyncGenerator:
        """Buffer the whole stream, classify, then release (or withhold). Nothing unclassified is sent."""
        POLICY.reload()
        buffered, text_parts, tool_parts, size = [], [], {}, 0
        withheld = None
        async for chunk in response:
            buffered.append(chunk)
            try:
                choices = getattr(chunk, "choices", None) or []
                if choices:
                    delta = getattr(choices[0], "delta", None)
                    piece = getattr(delta, "content", None) or ""
                    text_parts.append(piece); size += len(piece)
                    for tc in getattr(delta, "tool_calls", None) or []:
                        idx = getattr(tc, "index", 0) or 0
                        fn = getattr(tc, "function", None)
                        tool_parts.setdefault(idx, [getattr(fn, "name", "") or "", ""])
                        tool_parts[idx][0] = tool_parts[idx][0] or (getattr(fn, "name", "") or "")
                        tool_parts[idx][1] += getattr(fn, "arguments", "") or ""
                        size += len(getattr(fn, "arguments", "") or "")
            except Exception as e:  # noqa: BLE001 — fail closed
                audit("post_call_stream", "extraction_failure", str(e), request_data, user_api_key_dict)
                withheld = ["EXTRACTION_FAILURE"]
            if size > MAX_OUTPUT_CHARS:
                audit("post_call_stream", "output_buffer_cap", str(size), request_data, user_api_key_dict)
                withheld = ["OUTPUT_TOO_LONG"]
                break
        if not buffered:
            return
        if withheld is None:
            outputs = ["".join(text_parts)] + [f"{n} {a}" for n, a in tool_parts.values()]
            withheld = await self._check_output("post_call_stream", request_data, user_api_key_dict, [o for o in outputs if o.strip()])
        if withheld is None:
            for c in buffered:
                yield c
            return
        # Synthetic terminal chunk; never raise after headers are committed.
        try:
            first = copy.deepcopy(buffered[0])
            first.choices[0].delta.content = WITHHELD_MSG
            first.choices[0].delta.tool_calls = None
            first.choices[0].finish_reason = "content_filter"
            yield first
        except Exception:  # noqa: BLE001 — if even that fails, end the stream with nothing released
            return


proxy_handler_instance = VetoGuard()
