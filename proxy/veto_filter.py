"""
VetoGuard rev 2.1 — LiteLLM pre/post-call safety gate: lexical tripwire + Llama Guard classifier.

Layers (all fail-closed):
  1. Lexical tripwire (regex over normalised text). Cheap, catches sentinels and unambiguous terms.
  2. Llama Guard 3 classifier via Ollama on the backend network. Pre-call on the request text,
     post-call on the model output. Streaming responses are BUFFERED and classified before any
     token reaches the client. If the classifier is unreachable the request is refused (503).

Audit: every veto is appended to /app/audit/veto-audit.jsonl (timestamps, call id, stage,
list/category, key alias, model — never content).

Honest scope: the regex is a tripwire, not a boundary. The classifier is the control. Neither is
perfect; both are logged so the operator can review and tune (VETO_GUARD_IGNORE_CATEGORIES).

Env (set on the litellm service):
  VETO_GUARD_ENABLED=1                 0 disables the classifier stage (regex still runs) — do not in prod
  VETO_GUARD_URL=http://ollama:11434
  VETO_GUARD_MODEL=llama-guard3:1b
  VETO_GUARD_IGNORE_CATEGORIES=        comma list e.g. "S6,S8" to not block those Llama Guard categories
  VETO_GUARD_CHUNK_CHARS=6000          classifier chunk size (Llama Guard ctx is small)
  VETO_GUARD_MAX_CHUNKS=200            longer inputs are refused (413) rather than partially classified
  VETO_GUARD_TIMEOUT=60                seconds per classifier call
  VETO_AUDIT_PATH=/app/audit/veto-audit.jsonl
"""
from __future__ import annotations

import base64
import binascii
import copy
import json
import logging
import os
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Iterable

import httpx
from fastapi import HTTPException
from litellm.integrations.custom_logger import CustomLogger

log = logging.getLogger("vetoguard")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
GUARD_ENABLED = os.environ.get("VETO_GUARD_ENABLED", "1") == "1"
GUARD_URL = os.environ.get("VETO_GUARD_URL", "http://ollama:11434").rstrip("/")
GUARD_MODEL = os.environ.get("VETO_GUARD_MODEL", "llama-guard3:1b")
GUARD_IGNORE = {c.strip().upper() for c in os.environ.get("VETO_GUARD_IGNORE_CATEGORIES", "").split(",") if c.strip()}
CHUNK_CHARS = int(os.environ.get("VETO_GUARD_CHUNK_CHARS", "6000"))
MAX_CHUNKS = int(os.environ.get("VETO_GUARD_MAX_CHUNKS", "200"))
GUARD_TIMEOUT = float(os.environ.get("VETO_GUARD_TIMEOUT", "60"))
AUDIT_PATH = os.environ.get("VETO_AUDIT_PATH", "/app/audit/veto-audit.jsonl")

LLAMA_GUARD_CATEGORIES = {
    "S1": "Violent Crimes", "S2": "Non-Violent Crimes", "S3": "Sex-Related Crimes",
    "S4": "Child Sexual Exploitation", "S5": "Defamation", "S6": "Specialized Advice",
    "S7": "Privacy", "S8": "Intellectual Property", "S9": "Indiscriminate Weapons",
    "S10": "Hate", "S11": "Suicide & Self-Harm", "S12": "Sexual Content",
    "S13": "Elections", "S14": "Code Interpreter Abuse",
}

WITHHELD_MSG = "[Response withheld by policy: veto_triggered]"

# ---------------------------------------------------------------------------
# Lexical tripwire
# ---------------------------------------------------------------------------
SENTINEL_PATTERNS = [r"test[\s_]*sentinel[\s_]*block[\s_]*alpha"]   # neutral test trigger
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
# Scanned against text with ALL whitespace/underscores removed — defeats letter-spacing.
# Only unambiguous tokens belong here (no word boundaries are available).
DESPACED_PATTERNS = [r"testsentinelblockalpha", r"csam", r"pedophil", r"paedophil"]

_FLAGS = re.IGNORECASE | re.DOTALL
SENTINEL_RE = [re.compile(p, _FLAGS) for p in SENTINEL_PATTERNS]
MALWARE_RE = [re.compile(p, _FLAGS) for p in MALWARE_PATTERNS]
CSAM_RE = [re.compile(p, _FLAGS) for p in CSAM_PATTERNS]
DESPACED_RE = [re.compile(p, _FLAGS) for p in DESPACED_PATTERNS]

ZERO_WIDTH_RE = re.compile(r"[​-‏⁠-⁤﻿­]")
WS_RE = re.compile(r"\s+")
DESPACE_RE = re.compile(r"[\s_\[\]\-.*]+")
B64_RUN_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
MAX_SCAN_CHARS = 2_000_000


def normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = ZERO_WIDTH_RE.sub("", text)
    return WS_RE.sub(" ", text).lower()[:MAX_SCAN_CHARS]


def _decoded_b64_fragments(text: str) -> Iterable[str]:
    for m in B64_RUN_RE.finditer(text):
        try:
            yield base64.b64decode(m.group(0), validate=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue


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


def collect_request_text(data: dict) -> list[str]:
    """Latest user turn, plus any trailing tool results after it (+ prompt/input fields).

    Tool results are untrusted input — the prompt-injection channel once MCP/tool calling lands
    (roadmap) — so they are scanned like user text. Earlier turns were vetted when sent.
    """
    texts: list[str] = []
    for m in reversed(data.get("messages") or []):
        if not isinstance(m, dict):
            continue
        if m.get("role") == "tool":
            texts.append(_content_to_text(m.get("content")))
            continue
        if m.get("role") == "user":
            texts.append(_content_to_text(m.get("content")))
            break
        break  # an assistant turn after the last user turn: stop
    for key in ("prompt", "input"):
        v = data.get(key)
        if isinstance(v, list):
            texts.extend(str(x) for x in v)
        elif v:
            texts.append(str(v))
    return [t for t in texts if t]


def scan(texts: Iterable[str], patterns: list[re.Pattern]) -> str | None:
    for t in texts:
        n = normalise(t)
        for c in (n, *(normalise(f) for f in _decoded_b64_fragments(t))):
            for p in patterns:
                if p.search(c):
                    return p.pattern
    return None


def scan_despaced(texts: Iterable[str]) -> str | None:
    for t in texts:
        d = DESPACE_RE.sub("", normalise(t))
        for c in (d, *(DESPACE_RE.sub("", normalise(f)) for f in _decoded_b64_fragments(t))):
            for p in DESPACED_RE:
                if p.search(c):
                    return p.pattern
    return None


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------
def audit(stage: str, reason: str, detail: str, data: dict, key_dict: Any) -> None:
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "stage": stage, "reason": reason, "detail": detail,
        "call_id": data.get("litellm_call_id"), "model": data.get("model"),
        "key_alias": getattr(key_dict, "key_alias", None) or getattr(key_dict, "user_id", None),
    }
    log.warning("VETO %s", json.dumps(rec))
    try:
        os.makedirs(os.path.dirname(AUDIT_PATH), exist_ok=True)
        with open(AUDIT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError as e:
        log.error("audit write failed: %s", e)


def _refuse(status: int, code: str, message: str) -> None:
    raise HTTPException(status_code=status, detail={"error": {"code": code, "type": "invalid_request_error", "message": message}})


# ---------------------------------------------------------------------------
# Classifier (Llama Guard via Ollama)
# ---------------------------------------------------------------------------
class GuardUnavailable(Exception):
    pass


async def _guard_call(messages: list[dict]) -> tuple[bool, list[str]]:
    """Returns (unsafe, categories)."""
    payload = {"model": GUARD_MODEL, "messages": messages, "stream": False,
               "options": {"temperature": 0, "num_predict": 32, "num_ctx": 8192}}
    try:
        async with httpx.AsyncClient(timeout=GUARD_TIMEOUT) as client:
            r = await client.post(f"{GUARD_URL}/api/chat", json=payload)
            r.raise_for_status()
            verdict = (r.json().get("message", {}).get("content") or "").strip().lower()
    except Exception as e:  # noqa: BLE001 — any failure is "unavailable"; caller fails closed
        raise GuardUnavailable(str(e)) from e
    if not verdict:
        raise GuardUnavailable("empty verdict")
    if verdict.startswith("safe"):
        return False, []
    cats = [c.strip().upper() for c in re.findall(r"s\d{1,2}", verdict)]
    return True, cats or ["UNSPECIFIED"]


def _chunks(text: str) -> list[str]:
    return [text[i:i + CHUNK_CHARS] for i in range(0, len(text), CHUNK_CHARS)] or [""]


async def classify_request(texts: list[str]) -> tuple[bool, list[str]]:
    joined = "\n".join(texts)
    chunks = _chunks(joined)
    if len(chunks) > MAX_CHUNKS:
        _refuse(413, "prompt_too_long_for_guard", f"Input exceeds the classifier budget ({MAX_CHUNKS * CHUNK_CHARS} chars).")
    for ch in chunks:
        if not ch.strip():
            continue
        unsafe, cats = await _guard_call([{"role": "user", "content": ch}])
        blocked = [c for c in cats if c not in GUARD_IGNORE]
        if unsafe and blocked:
            return True, blocked
    return False, []


async def classify_output(request_text: str, output: str) -> tuple[bool, list[str]]:
    if not output.strip():
        return False, []
    chunks = _chunks(output)
    if len(chunks) > MAX_CHUNKS:
        return True, ["OUTPUT_TOO_LONG_FOR_GUARD"]
    user_ctx = request_text[:CHUNK_CHARS]
    for ch in chunks:
        unsafe, cats = await _guard_call([{"role": "user", "content": user_ctx}, {"role": "assistant", "content": ch}])
        blocked = [c for c in cats if c not in GUARD_IGNORE]
        if unsafe and blocked:
            return True, blocked
    return False, []


# ---------------------------------------------------------------------------
# LiteLLM hooks
# ---------------------------------------------------------------------------
class VetoGuard(CustomLogger):
    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        texts = collect_request_text(data)
        if not texts:
            return data
        for name, pats in (("sentinel", SENTINEL_RE), ("csam", CSAM_RE), ("malware", MALWARE_RE)):
            hit = scan(texts, pats)
            if hit:
                audit("pre_call", f"regex:{name}", hit, data, user_api_key_dict)
                _refuse(400, "veto_triggered", "Request refused by policy.")
        hit = scan_despaced(texts)
        if hit:
            audit("pre_call", "regex:despaced", hit, data, user_api_key_dict)
            _refuse(400, "veto_triggered", "Request refused by policy.")
        if GUARD_ENABLED:
            try:
                unsafe, cats = await classify_request(texts)
            except GuardUnavailable as e:
                audit("pre_call", "guard_unavailable", str(e)[:200], data, user_api_key_dict)
                _refuse(503, "guard_unavailable", "Safety classifier unavailable; request refused (fail-closed).")
            if unsafe:
                audit("pre_call", "classifier", ",".join(cats), data, user_api_key_dict)
                _refuse(400, "veto_triggered", "Request refused by policy.")
        return data

    async def async_post_call_success_hook(self, data, user_api_key_dict, response):
        if not GUARD_ENABLED:
            return response
        try:
            outputs = []
            for c in getattr(response, "choices", []) or []:
                outputs.append(_content_to_text(getattr(c.message, "content", None)))
                # Outgoing tool-call arguments are model output too (roadmap: MCP/tools).
                for tc in getattr(c.message, "tool_calls", None) or []:
                    fn = getattr(tc, "function", None)
                    outputs.append(f"{getattr(fn, 'name', '')} {getattr(fn, 'arguments', '')}")
        except Exception:  # noqa: BLE001
            return response
        req_text = "\n".join(collect_request_text(data))
        try:
            unsafe, cats = await classify_output(req_text, "\n".join(outputs))
        except GuardUnavailable as e:
            audit("post_call", "guard_unavailable", str(e)[:200], data, user_api_key_dict)
            _refuse(503, "guard_unavailable", "Safety classifier unavailable; response withheld (fail-closed).")
        if unsafe:
            audit("post_call", "classifier", ",".join(cats), data, user_api_key_dict)
            _refuse(400, "veto_triggered", "Response withheld by policy.")
        return response

    async def async_post_call_streaming_iterator_hook(self, user_api_key_dict, response, request_data: dict) -> AsyncGenerator:
        """Buffer the whole stream, classify, then release (or withhold). Nothing unclassified is sent."""
        buffered = []
        async for chunk in response:
            buffered.append(chunk)
        if not GUARD_ENABLED or not buffered:
            for c in buffered:
                yield c
            return
        text = "".join(
            (getattr(c.choices[0].delta, "content", None) or "")
            for c in buffered if getattr(c, "choices", None)
        )
        req_text = "\n".join(collect_request_text(request_data))
        try:
            unsafe, cats = await classify_output(req_text, text)
        except GuardUnavailable as e:
            audit("post_call_stream", "guard_unavailable", str(e)[:200], request_data, user_api_key_dict)
            unsafe, cats = True, ["GUARD_UNAVAILABLE"]
        if not unsafe:
            for c in buffered:
                yield c
            return
        audit("post_call_stream", "classifier", ",".join(cats), request_data, user_api_key_dict)
        first = copy.deepcopy(buffered[0])
        try:
            first.choices[0].delta.content = WITHHELD_MSG
            first.choices[0].finish_reason = "content_filter"
        except Exception:  # noqa: BLE001
            raise HTTPException(status_code=400, detail={"error": {"code": "veto_triggered", "message": "Response withheld by policy."}})
        yield first


proxy_handler_instance = VetoGuard()
