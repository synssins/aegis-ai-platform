"""
VetoGuard rev 2.7 — LiteLLM pre/post-call safety gate: lexical tripwire + Llama Guard classifier,
driven by an admin-editable policy file (hot-reloaded) that only the hub may write.

rev 2.7 (Agy round 5, docs/tests/agy-vetoguard-review-r5-2026-09-24.md): oversized multipart leaves are
never dropped; base64 fragments with stray non-printables are kept (cleaned) instead of discarded;
system-role messages always reach the classifier chunks; prefill windows are classified as-is (no
synthetic user turn); regex scans run on a dedicated bounded executor (saturation => refusal, never
bypass); streamed chunk COUNT is capped as well as bytes; indented base64 continuation lines accepted.
Optional admin diagnostics: policy "audit": {"store_snippet": true} stores <=160 chars of FLAGGED OUTPUT
(never for S4 / CSAM-tripwire reasons) in VETO_SNIPPET_PATH — default off.

rev 2.6 (Agy round 4, docs/tests/agy-vetoguard-review-r4-2026-09-24.md): the classifier's new segment
starts at the last user turn WITH TEXT (an empty trailing user turn no longer hides an earlier payload)
and includes tool-call arguments; the conversation window is always classified; streamed reasoning
is joined before scanning; base64 detection ignores zero-width/format characters and accepts 2-line
wraps; SchemaBudgetExceeded is handled (withhold) in the post-call paths; unknown multipart block
types contribute all their string leaves; relative audit paths work. Round-4 finding 3 (hook argument
order) is a false positive — verified against LiteLLM's CustomLogger source.

rev 2.5 (Agy round 3, docs/tests/agy-vetoguard-review-r3-2026-09-24.md): hook signatures are the ones
verified in LiteLLM's source (no argument-order guessing); top-level system + tool schemas reach the
CLASSIFIER, not only the tripwires; JSON keys are scanned and a schema-budget overflow REFUSES; base64
wrapped across lines is joined and decoded; the withhold chunk clears reasoning fields; streamed output
that yields nothing scannable is withheld; head+tail slicing instead of one-sided truncation; the ReDoS
probe covers more alphabets; the HTTP client is per event loop; audit rotation takes an flock and
exception text is reduced to class + short message.

rev 2.4 addresses the Agy adversarial review, round 2 (docs/tests/agy-vetoguard-review-r2-2026-09-24.md):
  1.1  history: an API client can fabricate earlier turns, so tripwires now run over EVERY message and
       the classifier sees the last CONVERSATION_WINDOW turns as a real multi-turn conversation (Llama
       Guard's intended mode) in addition to chunk-classifying the new segment. Full-history
       re-classification on every turn is deliberately NOT done (O(n²) over a chat); recorded trade-off.
  1.2  a request that carries messages/prompt/input but yields no scannable text is REFUSED (fail-closed);
       content parts of any type with text-like fields are extracted.
  1.3  schema traversal depth 24 with a node cap.
  2.1  responses may be dicts or objects.        2.2  reasoning/thinking fields are scanned.
  2.3  tool-call argument strings are JSON-unescaped before scanning.
  3.1  streaming aggregates every choice index (n>1); any unsafe choice withholds the stream.
  3.2  synthetic withhold chunk uses the first chunk that has a choice; never raises.
  4.1  decoded base64 fragments are part of the texts the CLASSIFIER sees (2.3 only fed the regex).
  4.2/4.3  base64 runs are matched on the original text (no whitespace collapsing) with threshold 16.
  4.4  lowercase Cyrillic/Greek confusables.     4.5  malware roots in the despaced list.
  5.1  process-wide classifier semaphore.        5.2  output context = the actual last user turn.
  5.3  first blocked verdict cancels the remaining chunk calls.   5.4  persistent HTTP client.
  6.1  ReDoS: admin patterns get a static nested-quantifier check plus a multi-charset timing probe; the
       per-request regex budget stays as the second line. (re2 is not available in this image.)
  6.2  a stat() failure keeps the previous policy.   6.3  probe is exception-safe.
  7.1/7.2  audit writes go through one bounded queue and one writer thread (locked rotation).
  7.3  hook argument order is detected, not assumed (LiteLLM's real order is (key, response, request)).

Layers (all fail-closed): 1. lexical tripwire  2. Llama Guard classifier (pre + post, streaming buffered).
Policy file: VETO_POLICY_PATH (default /app/policy/veto-policy.json), written by the hub. S4 always blocked.
Audit: VETO_AUDIT_PATH — timestamps, stage, reason/category, call id, key alias, model. Never content.
"""
from __future__ import annotations

import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
import binascii
import fcntl
import copy
import json
import logging
import os
import queue
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
SNIPPET_PATH = os.environ.get("VETO_SNIPPET_PATH", "/app/audit/veto-snippets.jsonl")
SNIPPET_CHARS = 160
NEVER_SNIPPET = ("S4", "csam", "despaced")
AUDIT_ROTATE_BYTES = 50 * 1024 * 1024
WITHHELD_MSG = "[Response withheld by policy: veto_triggered]"
SCAN_BUDGET_S = 5.0
MAX_OUTPUT_CHARS = 400_000
MAX_OUTPUT_CHUNKS = 20_000
POLICY_CHECK_INTERVAL_S = 2.0
CONVERSATION_WINDOW = 8
MAX_SCHEMA_NODES = 5000

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
    "audit": {"store_snippet": False},
}


# ---------------------------------------------------------------------------
# Policy (hot reload; keeps last good policy on any failure; rate-limited stat)
# ---------------------------------------------------------------------------
NESTED_QUANT_RE = re.compile(r"\([^()]*[+*][^()]*\)\s*[+*{]|\([^()]*\)[+*]\??\s*\([^()]*\)[+*]|\.\*.*\.\*.*\.\*")


def _pathological(pattern: str) -> bool:
    """True if the regex is invalid, statically suspicious, or slow on adversarial probes."""
    try:
        rx = re.compile(pattern, re.IGNORECASE | re.DOTALL)
    except re.error:
        return True
    if NESTED_QUANT_RE.search(pattern):
        return True
    alphabet = ("a", "z", "1", "0", " ", "\n", "x", "-", "_", ".", "/", "\\", "(", "é", "ж", "!", "\t", "=")
    probes = [(ch * 60 + tail) * 3 for ch in alphabet for tail in ("", "!", "aaaaaaaaaaaaaaaaaaaaaaaaaab", "ab" * 20)]
    t = time.perf_counter()
    try:
        for pr in probes:
            rx.search(pr)
            if time.perf_counter() - t > 0.1:
                return True
    except Exception:  # noqa: BLE001
        return True
    return False


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
            except FileNotFoundError:
                if self._mtime is None and not force:
                    return
                m = None
            except OSError as e:
                log.error("policy stat failed (%s); keeping previous policy", e)
                return
            if m == self._mtime and not force:
                return
            data = copy.deepcopy(DEFAULT_POLICY)
            if m is not None:
                try:
                    with open(POLICY_PATH, encoding="utf-8") as f:
                        loaded = json.load(f)
                    for k in ("guard", "tripwires", "audit"):
                        if isinstance(loaded.get(k), dict):
                            data[k].update(loaded[k])
                    if isinstance(loaded.get("categories"), dict):
                        for c, v in loaded["categories"].items():
                            if c in data["categories"] and isinstance(v, dict):
                                data["categories"][c]["block"] = bool(v.get("block", data["categories"][c]["block"]))
                except Exception as e:  # noqa: BLE001
                    log.error("policy read failed (%s); keeping previous policy", e)
                    return
            elif self._mtime is not None:
                log.error("policy file vanished; keeping previous policy")
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
    r"\b(reverse|bind)[\s\W_]*shell\b",
    r"\b(keylogger|ransomware|rootkit|botnet|credential[\s\W_]*stealer|info[\s\W_]*stealer)\b",
    r"\bc2[\s\W_]*(server|beacon|framework)\b",
    r"\b(bypass|evade|disable)[\s\W_]+(the[\s\W_]+)?(edr|antivirus|anti-virus|defender|amsi|security[\s\W_]*controls?)\b",
    r"\b(write|create|build|make)[\s\W_]+(me[\s\W_]+)?(a[\s\W_]+|some[\s\W_]+)?(malware|a[\s\W_]+virus|a[\s\W_]+worm|a[\s\W_]+trojan)\b",
]
CSAM_PATTERNS = [
    r"\b(child|children|underage|minor|minors|teen|teens|infant|toddler|preteen|kid|kids)\b"
    r".{0,60}?\b(porn|pornograph\w*|sex\w*|nude|naked|erotic\w*|explicit|molest\w*|abuse\w*)\b",
    r"\b(csam|csem|pedophil\w*|paedophil\w*|loli\w*|shota\w*)\b",
]
DESPACED_PATTERNS = [r"testsentinelblockalpha", r"csam", r"pedophil", r"paedophil",
                     r"reverseshell", r"bindshell", r"keylogger", r"ransomware", r"rootkit", r"c2beacon"]

_FLAGS = re.IGNORECASE | re.DOTALL
SENTINEL_RE = [re.compile(p, _FLAGS) for p in SENTINEL_PATTERNS]
MALWARE_RE = [re.compile(p, _FLAGS) for p in MALWARE_PATTERNS]
CSAM_RE = [re.compile(p, _FLAGS) for p in CSAM_PATTERNS]
DESPACED_RE = [re.compile(p, _FLAGS) for p in DESPACED_PATTERNS]
OUTPUT_TRIPWIRES = ("sentinel", "csam", "extra")

WS_RE = re.compile(r"\s+")
NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")
B64_RUN_RE = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_-])")
MAX_SCAN_CHARS = 2_000_000
CONFUSABLES = str.maketrans({
    # Cyrillic lower/upper -> Latin
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "т": "t", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ԛ": "q", "ԝ": "w", "ӏ": "l", "ь": "b", "ғ": "f", "ԍ": "g",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "У": "Y",
    "І": "I", "Ј": "J", "Ѕ": "S", "Ԁ": "D", "Ԛ": "Q", "Ԝ": "W",
    # Greek lower/upper -> Latin
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "γ": "y", "η": "n", "μ": "m", "ω": "w", "σ": "o", "ς": "s", "з": "3", "ԁ": "d",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
})


def normalise(text: str) -> str:
    text = text[:MAX_SCAN_CHARS]
    text = unicodedata.normalize("NFD", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) not in ("Mn", "Cf", "Cc") or ch in "\n\t")
    text = unicodedata.normalize("NFKC", text).translate(CONFUSABLES)
    return WS_RE.sub(" ", text).lower()


B64_BLOCK_RE = re.compile(r"(?:[ \t]*[A-Za-z0-9+/_-]{4,}={0,2}[ \t]*\r?\n){1,}[ \t]*[A-Za-z0-9+/_-]{4,}={0,2}")
FORMAT_CHARS_RE = re.compile(r"[\u200b-\u200f\u2060-\u2064\ufeff\u00ad]")


def _decoded_b64_fragments(text: str) -> list[str]:
    out = []
    text = FORMAT_CHARS_RE.sub("", text)
    joined = " ".join(re.sub(r"\s+", "", m.group(0)) for m in B64_BLOCK_RE.finditer(text))
    for m in B64_RUN_RE.finditer(text + ("\n" + joined if joined else "")):
        s = m.group(0).rstrip("=").replace("-", "+").replace("_", "/")
        s += "=" * (-len(s) % 4)
        try:
            dec = base64.b64decode(s, validate=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        clean = "".join(ch for ch in dec if ch.isprintable() or ch in "\n\t\r")
        if clean.strip() and len(clean) >= 0.5 * len(dec):
            out.append(clean)
    return out


def _unescape_json_string(s: str) -> str:
    """Tool-call arguments arrive as serialized JSON; recover the string leaves for scanning."""
    try:
        return "\n".join(_string_leaves(json.loads(s), 0))
    except (ValueError, TypeError):
        pass
    except SchemaBudgetExceeded:
        raise
    try:
        return json.loads(f'"{s}"') if "\\" in s else s
    except ValueError:
        return s


def _string_leaves(obj: Any, depth: int, budget: list | None = None) -> list[str]:
    budget = budget if budget is not None else [MAX_SCHEMA_NODES]
    if budget[0] <= 0 or depth > 24:
        raise SchemaBudgetExceeded("schema/argument structure exceeds scan budget")
    budget[0] -= 1
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [str(k) for k in obj.keys()] + [s for v in obj.values() for s in _string_leaves(v, depth + 1, budget)]
    if isinstance(obj, list):
        return [s for v in obj for s in _string_leaves(v, depth + 1, budget)]
    return []


def _content_to_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for p in content:
            if isinstance(p, str):
                parts.append(p)
            elif isinstance(p, dict):
                known = False
                for k in ("text", "input_text", "content", "refusal"):
                    v = p.get(k)
                    if isinstance(v, str):
                        parts.append(v); known = True
                    elif isinstance(v, list):
                        parts.append(_content_to_text(v)); known = True
                if not known and p.get("type") not in ("image_url", "input_image", "input_audio", "audio", "file"):
                    parts.extend(_string_leaves(p, 0))
        return "\n".join(x for x in parts if x)
    if isinstance(content, dict):
        return "\n".join(_string_leaves(content, 0))
    return str(content)


def _tool_calls_text(tcs: Any) -> str:
    parts = []
    for tc in tcs or []:
        fn = tc.get("function", {}) if isinstance(tc, dict) else getattr(tc, "function", None)
        name = (fn.get("name", "") if isinstance(fn, dict) else getattr(fn, "name", "")) or ""
        args = (fn.get("arguments", "") if isinstance(fn, dict) else getattr(fn, "arguments", "")) or ""
        parts.append(f"{name} {_unescape_json_string(args) if isinstance(args, str) else _content_to_text(args)}")
    return "\n".join(parts)


class SchemaBudgetExceeded(Exception):
    pass


class RequestView:
    """Everything scannable in a request, plus the conversation window for multi-turn classification."""

    def __init__(self, data: dict):
        msgs = [m for m in (data.get("messages") or []) if isinstance(m, dict)]
        self.has_payload = bool(msgs or data.get("prompt") or data.get("input") or data.get("system"))
        texts: list[str] = []
        self.turns: list[dict] = []
        for m in msgs:
            t = _content_to_text(m.get("content"))
            if m.get("tool_calls"):
                t = (t + "\n" + _tool_calls_text(m.get("tool_calls"))).strip()
            if t:
                texts.append(t)
                role = m.get("role", "user")
                if role == "tool":
                    t = "Tool result: " + t
                self.turns.append({"role": "assistant" if role == "assistant" else "user", "content": t})
        self.last_user = next((_content_to_text(m.get("content")) for m in reversed(msgs) if m.get("role") == "user" and _content_to_text(m.get("content")).strip()), "")
        last_user_idx = max((i for i, m in enumerate(msgs) if m.get("role") == "user" and _content_to_text(m.get("content")).strip()), default=0)
        self.new_segment = []
        for m in msgs[last_user_idx:]:
            t = _content_to_text(m.get("content"))
            if m.get("tool_calls"):
                t = (t + "\n" + _tool_calls_text(m.get("tool_calls"))).strip()
            if t:
                self.new_segment.append(t)
        for m in msgs:
            if m.get("role") in ("system", "developer"):
                sx = _content_to_text(m.get("content"))
                if sx:
                    self.new_segment.append(sx)
        if data.get("system"):
            sysx = _content_to_text(data.get("system"))
            texts.append(sysx); self.new_segment.append(sysx)
            self.turns.insert(0, {"role": "user", "content": "System instructions: " + sysx})
        for key in ("prompt", "input"):
            v = data.get(key)
            if isinstance(v, list):
                texts.extend(str(x) for x in v)
                self.new_segment.extend(str(x) for x in v)
            elif v:
                texts.append(str(v)); self.new_segment.append(str(v))
        for key in ("tools", "functions"):
            if data.get(key):
                sch = "\n".join(_string_leaves(data.get(key), 0))
                texts.append(sch); self.new_segment.append(sch)
        self.decoded = [d for t in texts for d in _decoded_b64_fragments(t)]
        self.all_texts = [t for t in texts + self.decoded if t and t.strip()]
        self.new_texts = [t for t in self.new_segment + self.decoded if t and t.strip()]


def scan(texts: Iterable[str], patterns: list[re.Pattern]) -> str | None:
    if not patterns:
        return None
    for t in texts:
        n = normalise(t)
        for p in patterns:
            if p.search(n):
                return p.pattern
    return None


def scan_despaced(texts: Iterable[str]) -> str | None:
    for t in texts:
        d = NON_ALNUM_RE.sub("", normalise(t))
        for p in DESPACED_RE:
            if p.search(d):
                return p.pattern
    return None


def tripwire_check(texts: list[str], lists: tuple[str, ...]) -> tuple[str, str] | None:
    table = {"sentinel": SENTINEL_RE, "csam": CSAM_RE, "malware": MALWARE_RE, "extra": POLICY.extra_re}
    for name in lists:
        hit = scan(texts, table[name])
        if hit:
            return name, hit
    hit = scan_despaced(texts)
    return ("despaced", hit) if hit else None


_SCAN_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="veto-scan")


async def tripwires(texts: list[str], lists: tuple[str, ...]):
    """Dedicated bounded pool: a ReDoS can stall at most 4 workers; queued scans then time out => refusal."""
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(loop.run_in_executor(_SCAN_POOL, tripwire_check, texts, lists), timeout=SCAN_BUDGET_S)
    except asyncio.TimeoutError:
        return "timeout"


# ---------------------------------------------------------------------------
# Audit: one bounded queue, one writer thread, locked rotation
# ---------------------------------------------------------------------------
_AUDIT_Q: queue.Queue = queue.Queue(maxsize=10000)


def _audit_writer() -> None:
    while True:
        rec = _AUDIT_Q.get()
        try:
            os.makedirs(os.path.dirname(AUDIT_PATH) or ".", exist_ok=True)
            with open(AUDIT_PATH + ".lock", "a") as lk:
                fcntl.flock(lk, fcntl.LOCK_EX)
                try:
                    try:
                        if os.path.getsize(AUDIT_PATH) > AUDIT_ROTATE_BYTES:
                            os.replace(AUDIT_PATH, AUDIT_PATH + "." + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
                    except OSError:
                        pass
                    with open(AUDIT_PATH, "a", encoding="utf-8") as f:
                        f.write(json.dumps(rec) + "\n")
                finally:
                    fcntl.flock(lk, fcntl.LOCK_UN)
        except OSError as e:
            log.error("audit write failed: %s", e)
        finally:
            _AUDIT_Q.task_done()


threading.Thread(target=_audit_writer, name="veto-audit-writer", daemon=True).start()


def _key_alias(key_dict: Any) -> str | None:
    if isinstance(key_dict, dict):
        return key_dict.get("key_alias") or key_dict.get("user_id")
    return getattr(key_dict, "key_alias", None) or getattr(key_dict, "user_id", None)


def _short_err(e: Any) -> str:
    return f"{type(e).__name__}: {str(e).splitlines()[0][:80]}" if isinstance(e, BaseException) else str(e)[:120]


def audit(stage: str, reason: str, detail: str, data: dict, key_dict: Any) -> None:
    rec = {"ts": datetime.now(timezone.utc).isoformat(), "stage": stage, "reason": reason, "detail": detail.splitlines()[0][:120] if detail else "",
           "call_id": data.get("litellm_call_id"), "model": data.get("model"), "key_alias": _key_alias(key_dict)}
    log.warning("VETO %s", json.dumps(rec))
    try:
        _AUDIT_Q.put_nowait(rec)
    except queue.Full:
        log.error("audit queue full; event dropped from file (still in process log)")


def snippet(stage: str, reason: str, detail: str, data: dict, key_dict: Any, text: str) -> None:
    """Admin-enabled diagnostics for flagged OUTPUT only. Never for S4 / CSAM-tripwire reasons."""
    if not POLICY.data.get("audit", {}).get("store_snippet"):
        return
    if any(x in detail for x in NEVER_SNIPPET) or any(x in reason for x in NEVER_SNIPPET):
        return
    rec = {"ts": datetime.now(timezone.utc).isoformat(), "stage": stage, "reason": reason, "detail": detail[:60],
           "call_id": data.get("litellm_call_id"), "key_alias": _key_alias(key_dict), "snippet": text.strip()[:SNIPPET_CHARS]}
    def _w():
        try:
            with open(SNIPPET_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
            os.chmod(SNIPPET_PATH, 0o600)
        except OSError as e:
            log.error("snippet write failed: %s", e)
    threading.Thread(target=_w, daemon=True).start()


def cats_str(cats: list[str]) -> str:
    """'S4 Child Sexual Exploitation, S1 Violent Crimes' — codes with names, for humans and alerts."""
    return ", ".join(f"{c} {LLAMA_GUARD_CATEGORIES[c]}" if c in LLAMA_GUARD_CATEGORIES else c for c in cats)


def _refuse(status: int, code: str, message: str) -> None:
    raise HTTPException(status_code=status, detail={"error": {"code": code, "type": "invalid_request_error", "message": message}})


# ---------------------------------------------------------------------------
# Classifier (Llama Guard via Ollama): shared client, process-wide concurrency, short-circuit
# ---------------------------------------------------------------------------
class GuardUnavailable(Exception):
    pass


_CLIENT: httpx.AsyncClient | None = None
_CLIENT_LOOP: asyncio.AbstractEventLoop | None = None
_SEM: asyncio.Semaphore | None = None
_SEM_LOOP: asyncio.AbstractEventLoop | None = None
_SEM_N: int = 0


def _client() -> httpx.AsyncClient:
    global _CLIENT, _CLIENT_LOOP
    loop = asyncio.get_running_loop()
    if _CLIENT is None or _CLIENT_LOOP is not loop:
        _CLIENT, _CLIENT_LOOP = httpx.AsyncClient(timeout=float(POLICY.guard.get("timeout", 60)), limits=httpx.Limits(max_connections=16)), loop
    return _CLIENT


def _sem() -> asyncio.Semaphore:
    global _SEM, _SEM_LOOP, _SEM_N
    loop = asyncio.get_running_loop()
    n = int(POLICY.guard.get("concurrency", 2))
    if _SEM is None or _SEM_LOOP is not loop or _SEM_N != n:
        _SEM, _SEM_LOOP, _SEM_N = asyncio.Semaphore(n), loop, n
    return _SEM


async def _guard_call(messages: list[dict]) -> tuple[bool, list[str]]:
    g = POLICY.guard
    payload = {"model": g["model"], "messages": messages, "stream": False,
               "options": {"temperature": 0, "num_predict": 32, "num_ctx": 8192}}
    try:
        async with _sem():
            r = await _client().post(f"{GUARD_URL}/api/chat", json=payload, timeout=float(g.get("timeout", 60)))
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


async def _classify_many(calls: list[list[dict]]) -> tuple[bool, list[str]]:
    """Run classifier calls; the first blocked verdict cancels the rest."""
    tasks = [asyncio.ensure_future(_guard_call(m)) for m in calls if m]
    try:
        for fut in asyncio.as_completed(tasks):
            unsafe, cats = await fut
            if unsafe and (b := _blocked_subset(cats)):
                return True, b
        return False, []
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()


def _headtail(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n // 2] + "\n…\n" + text[-(n // 2):]


def _window(turns: list[dict]) -> list[dict]:
    n = int(POLICY.guard.get("chunk_chars", 6000))
    w = turns[-CONVERSATION_WINDOW:]
    return [{"role": t["role"], "content": _headtail(t["content"], n)} for t in w]


async def classify_request(view: RequestView) -> tuple[bool, list[str]]:
    chunks = _chunks("\n".join(view.new_texts))
    if len(chunks) > int(POLICY.guard.get("max_chunks", 100)):
        _refuse(413, "prompt_too_long_for_guard", "Input exceeds the classifier budget.")
    calls = [[{"role": "user", "content": ch}] for ch in chunks if ch.strip()]
    w = _window(view.turns)
    if len(w) > 1:
        calls.append(w)                                   # multi-turn context classification (prefill evaluated as-is)
    return await _classify_many(calls)


async def classify_output(user_turn: str, outputs: list[str]) -> tuple[bool, list[str]]:
    text = "\n".join(o for o in outputs if o and o.strip())
    if not text.strip():
        return False, []
    chunks = _chunks(text)
    if len(chunks) > int(POLICY.guard.get("max_chunks", 100)):
        return True, ["OUTPUT_TOO_LONG_FOR_GUARD"]
    n = int(POLICY.guard.get("chunk_chars", 6000))
    ctx = _headtail(user_turn or "", n) or "(no user text)"
    return await _classify_many([[{"role": "user", "content": ctx}, {"role": "assistant", "content": ch}] for ch in chunks if ch.strip()])


# ---------------------------------------------------------------------------
# Response extraction (dict or object; content, reasoning, tool calls; every choice)
# ---------------------------------------------------------------------------
def _g(o: Any, k: str, default=None):
    return o.get(k, default) if isinstance(o, dict) else getattr(o, k, default)


REASONING_KEYS = ("reasoning_content", "reasoning", "thinking", "refusal")


def _message_outputs(msg: Any) -> list[str]:
    out = [_content_to_text(_g(msg, "content"))]
    for k in REASONING_KEYS:
        v = _g(msg, k)
        if v:
            out.append(_content_to_text(v))
    out.append(_tool_calls_text(_g(msg, "tool_calls")))
    return [o for o in out if o]


def extract_outputs(response: Any) -> list[str]:
    outs = []
    for c in _g(response, "choices", None) or []:
        msg = _g(c, "message", None) or _g(c, "delta", None)
        if msg is not None:
            outs.extend(_message_outputs(msg))
    return outs


# ---------------------------------------------------------------------------
# LiteLLM hooks
# ---------------------------------------------------------------------------
class VetoGuard(CustomLogger):
    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        POLICY.reload()
        try:
            view = RequestView(data)
        except SchemaBudgetExceeded as e:
            audit("pre_call", "schema_budget_exceeded", str(e), data, user_api_key_dict)
            _refuse(413, "veto_triggered", "Request structure too large to evaluate; refused (fail-closed).")
        if not view.all_texts:
            if view.has_payload:
                audit("pre_call", "no_scannable_text", call_type or "", data, user_api_key_dict)
                _refuse(400, "veto_triggered", "Request carries content that cannot be evaluated; refused (fail-closed).")
            return data
        if POLICY.data["tripwires"].get("enabled", True):
            hit = await tripwires(view.all_texts, ("sentinel", "csam", "malware", "extra"))
            if hit == "timeout":
                audit("pre_call", "regex_budget_exhausted", "", data, user_api_key_dict)
                _refuse(400, "veto_triggered", "Request refused by policy.")
            if hit:
                audit("pre_call", f"regex:{hit[0]}", hit[1], data, user_api_key_dict)
                _refuse(400, "veto_triggered", "Request refused by policy.")
        try:
            unsafe, cats = await classify_request(view)
        except GuardUnavailable as e:
            audit("pre_call", "guard_unavailable", _short_err(e), data, user_api_key_dict)
            _refuse(503, "guard_unavailable", "Safety classifier unavailable; request refused (fail-closed).")
        if unsafe:
            audit("pre_call", "classifier", cats_str(cats), data, user_api_key_dict)
            _refuse(400, "veto_triggered", "Request refused by policy.")
        return data

    async def _check_output(self, stage: str, data: dict, key: Any, outputs: list[str]) -> list[str] | None:
        outputs = [o for o in outputs if o and o.strip()]
        outputs += [d for o in outputs for d in _decoded_b64_fragments(o)]
        if not outputs:
            return None
        if POLICY.data["tripwires"].get("enabled", True):
            hit = await tripwires(outputs, OUTPUT_TRIPWIRES)
            if hit == "timeout":
                audit(stage, "regex_budget_exhausted", "", data, key); return ["REGEX_BUDGET"]
            if hit:
                audit(stage, f"regex:{hit[0]}", hit[1], data, key); snippet(stage, f"regex:{hit[0]}", hit[1], data, key, "\n".join(outputs)); return [hit[0]]
        try:
            try:
                last_user = RequestView(data).last_user
            except SchemaBudgetExceeded:
                last_user = ""
            unsafe, cats = await classify_output(last_user, outputs)
        except GuardUnavailable as e:
            audit(stage, "guard_unavailable", _short_err(e), data, key); return ["GUARD_UNAVAILABLE"]
        if unsafe:
            audit(stage, "classifier", cats_str(cats), data, key); snippet(stage, "classifier", cats_str(cats), data, key, "\n".join(outputs)); return cats
        return None

    async def async_post_call_success_hook(self, data, user_api_key_dict, response):
        POLICY.reload()
        try:
            outputs = extract_outputs(response)
        except SchemaBudgetExceeded as e:
            audit("post_call", "schema_budget_exceeded", _short_err(e), data, user_api_key_dict)
            _refuse(400, "veto_triggered", "Response structure too large to evaluate; withheld (fail-closed).")
        except Exception as e:  # noqa: BLE001 — fail closed
            audit("post_call", "extraction_failure", _short_err(e), data, user_api_key_dict)
            _refuse(500, "safety_processing_error", "Response could not be evaluated; withheld (fail-closed).")
        if (_g(response, "choices", None) or []) and not outputs:
            audit("post_call", "no_scannable_output", "", data, user_api_key_dict)
            _refuse(400, "veto_triggered", "Response could not be evaluated; withheld (fail-closed).")
        reasons = await self._check_output("post_call", data, user_api_key_dict, outputs)
        if reasons:
            if "GUARD_UNAVAILABLE" in reasons:
                _refuse(503, "guard_unavailable", "Safety classifier unavailable; response withheld (fail-closed).")
            _refuse(400, "veto_triggered", "Response withheld by policy.")
        return response

    async def async_post_call_streaming_iterator_hook(self, user_api_key_dict, response, request_data: dict) -> AsyncGenerator:
        """Buffer the whole stream, classify every choice, then release (or withhold). Nothing unclassified is sent."""
        POLICY.reload()
        buffered, per_choice, size, withheld = [], {}, 0, None
        async for chunk in response:
            buffered.append(chunk)
            try:
                for ch in _g(chunk, "choices", None) or []:
                    idx = _g(ch, "index", 0) or 0
                    delta = _g(ch, "delta", None)
                    if delta is None:
                        continue
                    slot = per_choice.setdefault(idx, {"text": [], "reason": [], "tools": {}})
                    piece = _content_to_text(_g(delta, "content"))
                    if piece:
                        slot["text"].append(piece); size += len(piece)
                    for k in REASONING_KEYS:
                        v = _g(delta, k)
                        if v:
                            slot["reason"].append(_content_to_text(v)); size += len(str(v))
                    for tc in _g(delta, "tool_calls", None) or []:
                        ti = _g(tc, "index", 0) or 0
                        fn = _g(tc, "function", None)
                        t = slot["tools"].setdefault(ti, ["", ""])
                        t[0] = t[0] or (_g(fn, "name", "") or "")
                        args = _g(fn, "arguments", "") or ""
                        t[1] += args; size += len(args)
            except Exception as e:  # noqa: BLE001 — fail closed
                audit("post_call_stream", "extraction_failure", _short_err(e), request_data, user_api_key_dict)
                withheld = ["EXTRACTION_FAILURE"]; break
            if size > MAX_OUTPUT_CHARS or len(buffered) > MAX_OUTPUT_CHUNKS:
                audit("post_call_stream", "output_buffer_cap", f"{size} chars / {len(buffered)} chunks", request_data, user_api_key_dict)
                withheld = ["OUTPUT_TOO_LONG"]; break
        if not buffered:
            return
        if withheld is None:
            outputs = []
            try:
                for slot in per_choice.values():
                    outputs.append("".join(slot["text"]))
                    outputs.append("".join(slot["reason"]))
                    outputs.extend(f"{n} {_unescape_json_string(a)}" for n, a in slot["tools"].values())
            except SchemaBudgetExceeded as e:
                audit("post_call_stream", "schema_budget_exceeded", _short_err(e), request_data, user_api_key_dict)
                outputs, withheld = [], ["SCHEMA_BUDGET"]
            if withheld is None and any(_g(c, "choices", None) for c in buffered) and not any(o and o.strip() for o in outputs):
                audit("post_call_stream", "no_scannable_output", "", request_data, user_api_key_dict)
                withheld = ["NO_SCANNABLE_OUTPUT"]
            elif withheld is None:
                withheld = await self._check_output("post_call_stream", request_data, user_api_key_dict, outputs)
        if withheld is None:
            for c in buffered:
                yield c
            return
        try:
            src = next((c for c in buffered if _g(c, "choices", None)), None)
            if src is None:
                return
            first = copy.deepcopy(src)
            for ch in _g(first, "choices"):
                d = _g(ch, "delta", None)
                if d is not None:
                    if isinstance(d, dict):
                        d["content"], d["tool_calls"] = WITHHELD_MSG, None
                        for k in REASONING_KEYS:
                            d.pop(k, None)
                    else:
                        d.content, d.tool_calls = WITHHELD_MSG, None
                        for k in REASONING_KEYS:
                            if hasattr(d, k):
                                try: setattr(d, k, None)
                                except Exception: pass  # noqa: BLE001
                if isinstance(ch, dict):
                    ch["finish_reason"] = "content_filter"
                else:
                    ch.finish_reason = "content_filter"
            yield first
        except Exception:  # noqa: BLE001
            return


proxy_handler_instance = VetoGuard()
