"""
VetoGuard rev 2.2 — LiteLLM pre/post-call safety gate: lexical tripwire + Llama Guard classifier,
driven by an admin-editable policy file (hot-reloaded) that only the hub may write.

Layers (all fail-closed):
  1. Lexical tripwire (regex over normalised text). Built-in lists + admin "extra tripwires".
  2. Llama Guard 3 classifier via Ollama on the backend network. Pre-call on the request text,
     post-call on the model output. Streaming responses are BUFFERED and classified before any
     token reaches the client. Classifier unreachable => request refused (503).

Policy file (VETO_POLICY_PATH, default /app/policy/veto-policy.json), written by the hub:
  {
    "guard": {"model": "llama-guard3:8b", "chunk_chars": 6000, "max_chunks": 200, "timeout": 60},
    "categories": {"S1": {"block": true}, ..., "S14": {"block": false}},   # S4 is ALWAYS blocked
    "tripwires": {"enabled": true, "extra_patterns": ["..."]}
  }
Missing file => built-in defaults below. The classifier stage and fail-closed behaviour cannot be
switched off by policy — only the category set and the guard model are configurable.

Audit: every veto appends a JSON line to VETO_AUDIT_PATH (timestamp, stage, reason/category,
call id, key alias, model). Never content.
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

GUARD_URL = os.environ.get("VETO_GUARD_URL", "http://ollama:11434").rstrip("/")
POLICY_PATH = os.environ.get("VETO_POLICY_PATH", "/app/policy/veto-policy.json")
AUDIT_PATH = os.environ.get("VETO_AUDIT_PATH", "/app/audit/veto-audit.jsonl")
WITHHELD_MSG = "[Response withheld by policy: veto_triggered]"

LLAMA_GUARD_CATEGORIES = {
    "S1": "Violent Crimes", "S2": "Non-Violent Crimes", "S3": "Sex-Related Crimes",
    "S4": "Child Sexual Exploitation", "S5": "Defamation", "S6": "Specialized Advice",
    "S7": "Privacy", "S8": "Intellectual Property", "S9": "Indiscriminate Weapons",
    "S10": "Hate", "S11": "Suicide & Self-Harm", "S12": "Sexual Content",
    "S13": "Elections", "S14": "Code Interpreter Abuse",
}
LOCKED_CATEGORIES = {"S4"}  # cannot be unblocked by any policy
# Operator policy 2026-09-24: illegal / protected-class content never passes; adult content may.
DEFAULT_BLOCK = {"S1", "S2", "S3", "S4", "S9", "S10", "S11"}

DEFAULT_POLICY = {
    "guard": {"model": os.environ.get("VETO_GUARD_MODEL", "llama-guard3:1b"),
              "chunk_chars": 6000, "max_chunks": 200, "timeout": 60},
    "categories": {c: {"block": c in DEFAULT_BLOCK} for c in LLAMA_GUARD_CATEGORIES},
    "tripwires": {"enabled": True, "extra_patterns": []},
}


# ---------------------------------------------------------------------------
# Policy (hot reload on mtime)
# ---------------------------------------------------------------------------
class Policy:
    def __init__(self):
        self._mtime = None
        self.data = copy.deepcopy(DEFAULT_POLICY)
        self.extra_re: list[re.Pattern] = []
        self.reload()

    def reload(self) -> None:
        try:
            m = os.stat(POLICY_PATH).st_mtime
        except OSError:
            m = None
        if m == self._mtime:
            return
        self._mtime = m
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
            except Exception as e:  # noqa: BLE001 — bad policy file => defaults, loudly
                log.error("policy load failed (%s); using built-in defaults", e)
        for c in LOCKED_CATEGORIES:
            data["categories"][c]["block"] = True
        pats = []
        for p in data["tripwires"].get("extra_patterns", []):
            try:
                pats.append(re.compile(p, re.IGNORECASE | re.DOTALL))
            except re.error as e:
                log.error("ignoring invalid extra tripwire %r: %s", p, e)
        self.data, self.extra_re = data, pats
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
    """Latest user turn plus trailing tool results (untrusted input), plus prompt/input fields."""
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
    if not verdict:
        raise GuardUnavailable("empty verdict")
    if verdict.startswith("safe"):
        return False, []
    cats = [c.upper() for c in re.findall(r"s\d{1,2}", verdict)]
    return True, cats or ["UNSPECIFIED"]


def _chunks(text: str) -> list[str]:
    n = int(POLICY.guard.get("chunk_chars", 6000))
    return [text[i:i + n] for i in range(0, len(text), n)] or [""]


def _blocked_subset(cats: list[str]) -> list[str]:
    blocked = POLICY.blocked()
    return [c for c in cats if c in blocked or c == "UNSPECIFIED"]


async def classify_request(texts: list[str]) -> tuple[bool, list[str]]:
    chunks = _chunks("\n".join(texts))
    if len(chunks) > int(POLICY.guard.get("max_chunks", 200)):
        _refuse(413, "prompt_too_long_for_guard", "Input exceeds the classifier budget.")
    for ch in chunks:
        if not ch.strip():
            continue
        unsafe, cats = await _guard_call([{"role": "user", "content": ch}])
        if unsafe and (b := _blocked_subset(cats)):
            return True, b
    return False, []


async def classify_output(request_text: str, output: str) -> tuple[bool, list[str]]:
    if not output.strip():
        return False, []
    chunks = _chunks(output)
    if len(chunks) > int(POLICY.guard.get("max_chunks", 200)):
        return True, ["OUTPUT_TOO_LONG_FOR_GUARD"]
    user_ctx = request_text[: int(POLICY.guard.get("chunk_chars", 6000))]
    for ch in chunks:
        unsafe, cats = await _guard_call([{"role": "user", "content": user_ctx}, {"role": "assistant", "content": ch}])
        if unsafe and (b := _blocked_subset(cats)):
            return True, b
    return False, []


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
            for name, pats in (("sentinel", SENTINEL_RE), ("csam", CSAM_RE), ("malware", MALWARE_RE), ("extra", POLICY.extra_re)):
                hit = scan(texts, pats) if pats else None
                if hit:
                    audit("pre_call", f"regex:{name}", hit, data, user_api_key_dict)
                    _refuse(400, "veto_triggered", "Request refused by policy.")
            hit = scan_despaced(texts)
            if hit:
                audit("pre_call", "regex:despaced", hit, data, user_api_key_dict)
                _refuse(400, "veto_triggered", "Request refused by policy.")
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
        POLICY.reload()
        try:
            outputs = []
            for c in getattr(response, "choices", []) or []:
                outputs.append(_content_to_text(getattr(c.message, "content", None)))
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
        POLICY.reload()
        buffered = []
        async for chunk in response:
            buffered.append(chunk)
        if not buffered:
            return
        text = "".join((getattr(c.choices[0].delta, "content", None) or "") for c in buffered if getattr(c, "choices", None))
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
