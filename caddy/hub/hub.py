#!/usr/bin/env python3
"""
Aegis Hub v3 — admin control centre with its own authentication.

Auth (replaces Caddy basic-auth):
  * users in /app/state/users.json — argon2id hashes only (no reversible secret anywhere);
  * TOTP (RFC 6238) required for every account; the TOTP secret is Fernet-encrypted at rest with
    HUB_SECRET_KEY; replay of a used code is rejected;
  * sessions are HMAC-signed, HttpOnly, Secure, SameSite=Strict cookies scoped to /hub, 12 h;
  * lockout: 5 failures per user => 5 min; 20 failures per client IP => 15 min; all audited;
  * first run: no administrator exists => /hub serves a setup wizard (choose the admin username, set a
    policy-checked password, enroll MFA) entirely in the browser. Nothing is printed or stored in files.
  * console recovery: `python3 /app/hub.py --reset-admin` REMOVES the administrator, which makes the
    wizard reappear (scripts/hub-reset-admin.sh). No bootstrap passwords exist anywhere.

Control (via the host watchdog, never a Docker socket in a container):
  * the hub writes exactly one /app/ops/requests/request.json; the watchdog executes and answers in
    /app/ops/responses/; caddy/hub can only be restarted, never stopped; one request at a time.

Everything else as v2: VetoGuard policy (S4 locked), audit log + snippets, alerts, models (pull /
load / unload / remove / expose), API keys, certificates, public hostname (Cloudflare DNS-01),
isolation view. Every state change is audited and alerted. Stdlib + argon2-cffi + cryptography.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken

# ---------------------------------------------------------------- config / paths ----------
LAN_IP = os.environ.get("AEGIS_LAN_IP", "127.0.0.1")
MASTER_KEY = os.environ.get("LITELLM_MASTER_KEY", "")
SECRET = os.environ.get("HUB_SECRET_KEY", "")
GRAFANA_ENABLED = os.environ.get("GRAFANA_ENABLED", "0") == "1"
CADDYFILE = "/etc/caddy/Caddyfile"
COMPOSE_VIEW = "/app/view/docker-compose.yml"
SITES_DIR = "/etc/caddy/sites-enabled"
DOMAIN_FILE = os.path.join(SITES_DIR, "domain.caddy")
POLICY_FILE = "/app/policy/veto-policy.json"
STATE_DIR = "/app/state"
STATE_FILE = os.path.join(STATE_DIR, "hub.json")
USERS_FILE = os.path.join(STATE_DIR, "users.json")
AUDIT_DIR = "/app/audit"
HUB_AUDIT = os.path.join(AUDIT_DIR, "hub-audit.jsonl")
VETO_AUDIT = os.path.join(AUDIT_DIR, "veto-audit.jsonl")
SNIPPETS = os.path.join(AUDIT_DIR, "veto-snippets.jsonl")
OPS_REQ = "/app/ops/requests/request.json"
OPS_RESP = "/app/ops/responses"
OPS_STATUS = os.path.join(OPS_RESP, "status.json")
CADDY_ADMIN = "http://127.0.0.1:2019"
LITELLM = "http://litellm:4000"
OLLAMA = "http://ollama:11434"
MODELD = "http://modeld:11434"
CSRF = secrets.token_urlsafe(24)
SESSION_TTL = 12 * 3600
PH = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")
CF_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{30,80}$")
MODEL_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,120}(:[a-z0-9._-]{1,60})?$")
ALIAS_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,40}$")
USER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,30}$")

CATEGORIES = {
    "S1": ("Violent crimes", "illegal"), "S2": ("Non-violent crimes", "illegal"), "S3": ("Sex-related crimes", "illegal"),
    "S4": ("Child sexual exploitation", "locked"), "S5": ("Defamation", "adult/legal"), "S6": ("Specialized advice", "adult/legal"),
    "S7": ("Privacy", "adult/legal"), "S8": ("Intellectual property", "adult/legal"), "S9": ("Indiscriminate weapons", "illegal"),
    "S10": ("Hate (protected classes)", "protected"), "S11": ("Suicide & self-harm", "protected"), "S12": ("Sexual content (adult)", "adult/legal"),
    "S13": ("Elections", "adult/legal"), "S14": ("Code interpreter abuse", "adult/legal"),
}
DEFAULT_BLOCK = {"S1", "S2", "S3", "S4", "S9", "S10", "S11"}
DEFAULT_POLICY = {"guard": {"model": "llama-guard3:1b", "chunk_chars": 6000, "chunk_overlap": 600, "max_chunks": 100, "timeout": 60, "concurrency": 2},
                  "categories": {c: {"block": c in DEFAULT_BLOCK} for c in CATEGORIES},
                  "tripwires": {"enabled": True, "extra_patterns": []}, "audit": {"store_snippet": False}, "updated": None, "updated_by": None}

SERVICES = {  # name -> (purpose, network, protected)
    "caddy": ("Gateway: TLS, routing, edge auth", "edge", True), "hub": ("This admin console", "edge (caddy netns)", True),
    "openwebui": ("Chat interface", "edge", False), "litellm": ("OpenAI-compatible API + VetoGuard", "edge/backend", False),
    "litellm-db": ("Key/model store for LiteLLM", "backend", False), "ollama": ("Inference engine (GPU)", "backend", False),
    "modeld": ("Model pulls (only container with internet + model store)", "mgmt", False),
    "prometheus": ("Metrics store", "monitoring", False), "grafana": ("Dashboards", "monitoring/edge", False),
    "node-exporter": ("Host metrics", "monitoring", False), "dcgm-exporter": ("GPU metrics", "monitoring", False),
    "fish-speech": ("Text-to-speech (apps profile)", "apps", False), "comfyui": ("Image generation (apps profile, gated)", "apps", False),
}

DOMAIN_TEMPLATE = """# GENERATED BY AEGIS HUB {ts} — regenerate from /hub or delete on the console. Do not hand-edit.
{hostname} {{
    tls {{
        dns cloudflare {token}
    }}
    import site
}}
"""

NAV = [
    ("overview", "Overview", [("dashboard", "Dashboard"), ("services", "Services")]),
    ("safety", "Safety", [("policy", "VetoGuard policy"), ("audit", "Audit log"), ("alerts", "Alerts")]),
    ("models", "Models", [("installed", "Installed"), ("pull", "Pull"), ("exposed", "Exposed to apps")]),
    ("access", "Access", [("keys", "API keys"), ("account", "Admin account")]),
    ("gateway", "Gateway", [("certs", "Certificates"), ("hostname", "Public hostname"), ("isolation", "Isolation (read-only)")]),
]
PAGE_SIZES = (10, 25, 50, 100)
ALERT_ON = ("S1 ", "S2 ", "S3 ", "S4 ", "S9 ", "S10 ", "S11 ", "regex:csam", "regex:despaced", "regex:extra", "regex:malware",
            "guard_verdict_unparseable", "guard_no_adapter", "guard_unavailable")
ADAPTER_RE = re.compile(r"llama-?guard", re.I)   # families with a verdict adapter in proxy/veto_filter.py


def has_adapter(model: str) -> bool:
    return bool(ADAPTER_RE.search(model or ""))

JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()
REQ = threading.local()
FAILS: dict[str, list[float]] = {}      # key -> failure timestamps
FAILS_LOCK = threading.Lock()


# ---------------------------------------------------------------- utilities ----------------
def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(path, data) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def state() -> dict:
    return load_json(STATE_FILE, {"webhook": "", "hostname": ""})


def q(key, default=""):
    return getattr(REQ, "q", {}).get(key, [default])[0]


def http(method, url, body=None, headers=None, timeout=15):
    data = json.dumps(body).encode() if isinstance(body, (dict, list)) else (body.encode() if isinstance(body, str) else body)
    h = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode(errors="replace"); st = r.status
    except urllib.error.HTTPError as e:
        raw, st = e.read().decode(errors="replace"), e.code
    except Exception as e:  # noqa: BLE001
        return 0, str(e)
    try:
        return st, json.loads(raw)
    except ValueError:
        return st, raw


def litellm(method, path, body=None):
    return http(method, LITELLM + path, body, {"Authorization": f"Bearer {MASTER_KEY}"}, timeout=30)


def audit(event: str, **fields) -> None:
    actor = getattr(REQ, "user", None) or "system"
    rec = {"ts": now(), "actor": actor, "event": event, **fields}
    try:
        os.makedirs(AUDIT_DIR, exist_ok=True)
        with open(HUB_AUDIT, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError as e:
        print(f"audit write failed: {e}", file=sys.stderr)
    alert(f"[aegis-hub] {event} by {actor}: " + ", ".join(f"{k}={v}" for k, v in fields.items() if k not in ("token",)))


def alert(text: str) -> None:
    url = state().get("webhook", "")
    if not url:
        return
    threading.Thread(target=lambda: http("POST", url, {"text": text, "content": text, "source": "aegis-hub", "ts": now()}, timeout=5), daemon=True).start()


def tail_jsonl(path, n=200):
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()[-n:]
    except OSError:
        return []
    out = []
    for l in reversed(lines):
        try:
            out.append(json.loads(l))
        except ValueError:
            continue
    return out


def paginate(rows, key, default_per=25):
    try: per = int(q(f"{key}_per", default_per))
    except ValueError: per = default_per
    per = per if per in PAGE_SIZES else default_per
    total = len(rows); pages = max(1, (total + per - 1) // per)
    try: pg = min(max(1, int(q(f"{key}_page", 1))), pages)
    except ValueError: pg = 1
    path = getattr(REQ, "path", "/hub")
    other = {k: v[0] for k, v in getattr(REQ, "q", {}).items() if not k.startswith(key + "_")}
    def link(p, n):
        return path + "?" + urllib.parse.urlencode({**other, f"{key}_per": str(n), f"{key}_page": str(p)})
    sizes = " ".join(f'<a href="{link(1, n)}"{" class=on" if n == per else ""}>{n}</a>' for n in PAGE_SIZES)
    prev = f'<a href="{link(pg - 1, per)}">&larr; prev</a>' if pg > 1 else '<span class="mut">&larr; prev</span>'
    nxt = f'<a href="{link(pg + 1, per)}">next &rarr;</a>' if pg < pages else '<span class="mut">next &rarr;</span>'
    ctl = f'<div class="pager"><span>per page: {sizes}</span><span>{prev} &nbsp; page {pg} / {pages} &nbsp; {nxt}</span><span class="mut">{total} entries</span></div>'
    return rows[(pg - 1) * per: pg * per], ctl


# ---------------------------------------------------------------- auth ---------------------
def fernet() -> Fernet:
    key = hashlib.sha256(SECRET.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def users() -> dict:
    return load_json(USERS_FILE, {})


def save_users(u: dict) -> None:
    save_json(USERS_FILE, u)


def totp_now(secret_b32: str, at: float | None = None) -> str:
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    counter = int((at or time.time()) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def totp_verify(secret_b32: str, code: str, last_counter: int) -> int | None:
    """Returns the matched counter (for replay protection) or None."""
    code = re.sub(r"\D", "", code or "")
    if len(code) != 6:
        return None
    base = int(time.time() // 30)
    for c in (base - 1, base, base + 1):
        if c <= last_counter:
            continue
        if hmac.compare_digest(totp_now(secret_b32, c * 30), code):
            return c
    return None


def password_policy(pw: str) -> str | None:
    if len(pw) < 14: return "too short (minimum 14 characters)"
    if len(pw) > 128: return "too long (maximum 128)"
    if any(ch.isspace() for ch in pw): return "must not contain spaces"
    classes = sum([any(c.islower() for c in pw), any(c.isupper() for c in pw), any(c.isdigit() for c in pw), any(not c.isalnum() for c in pw)])
    if classes < 3: return "needs at least three of: lowercase, uppercase, digit, symbol"
    if any(w in pw.lower() for w in ("admin", "aegis", "password", "qwerty", "123456")): return "contains a forbidden word"
    return None


def reset_admin() -> None:
    """Console recovery: remove every account so the first-run wizard runs again."""
    save_users({})
    print("All hub accounts removed. Open /hub in a browser to run the setup wizard (create admin, enroll MFA).", flush=True)
    audit("admin_reset_wizard_rearmed")


def setup_needed() -> bool:
    return not users()


def sign(payload: dict) -> str:
    raw = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = hmac.new(SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"


def unsign(token: str) -> dict | None:
    try:
        raw, sig = token.split(".", 1)
        if not hmac.compare_digest(hmac.new(SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest(), sig):
            return None
        d = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        return d if d.get("exp", 0) > time.time() else None
    except Exception:  # noqa: BLE001
        return None


def client_ip(h: BaseHTTPRequestHandler) -> str:
    return (h.headers.get("X-Forwarded-For", "").split(",")[0].strip() or h.client_address[0])


def locked(key: str, limit: int, window: int) -> bool:
    with FAILS_LOCK:
        ts = [t for t in FAILS.get(key, []) if time.time() - t < window]
        FAILS[key] = ts
        return len(ts) >= limit


def fail(key: str) -> None:
    with FAILS_LOCK:
        FAILS.setdefault(key, []).append(time.time())


def clear_fail(key: str) -> None:
    with FAILS_LOCK:
        FAILS.pop(key, None)


# ---------------------------------------------------------------- domain objects ----------
def policy() -> dict:
    p = load_json(POLICY_FILE, None) or json.loads(json.dumps(DEFAULT_POLICY))
    for c in CATEGORIES:
        p.setdefault("categories", {}).setdefault(c, {"block": c in DEFAULT_BLOCK})
    p["categories"]["S4"]["block"] = True
    p.setdefault("guard", DEFAULT_POLICY["guard"].copy()); p.setdefault("tripwires", {"enabled": True, "extra_patterns": []}); p.setdefault("audit", {"store_snippet": False})
    return p


_CAPS: dict[str, list[str]] = {}


def model_caps(name: str) -> list[str]:
    """Ollama's declared capabilities (completion, tools, vision, embedding, thinking). Cached per name."""
    if name not in _CAPS:
        st, j = http("POST", OLLAMA + "/api/show", {"model": name}, timeout=20)
        _CAPS[name] = sorted(j.get("capabilities", [])) if isinstance(j, dict) else []
    return _CAPS[name]


CAP_ICONS = {  # 16x16 inline SVG, currentColor; title = capability
    "vision": ("Vision (accepts images)", '<path d="M1 8s2.5-5 7-5 7 5 7 5-2.5 5-7 5-7-5-7-5z" fill="none" stroke="currentColor" stroke-width="1.4"/><circle cx="8" cy="8" r="2.2" fill="currentColor"/>'),
    "tools": ("Tool calls (can drive assistants such as Home Assistant)", '<path d="M10.5 2.2a3.3 3.3 0 0 0-3.1 4.4L2.2 11.8a1.3 1.3 0 0 0 1.9 1.9l5.2-5.2a3.3 3.3 0 0 0 4.4-3.1l-2 2-1.6-.4-.4-1.6z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/>'),
    "thinking": ("Thinking / reasoning output", '<path d="M6 2.5a2.5 2.5 0 0 0-2.4 3.1A2.5 2.5 0 0 0 3 10a2.5 2.5 0 0 0 3 2.4V2.5zm4 0a2.5 2.5 0 0 1 2.4 3.1A2.5 2.5 0 0 1 13 10a2.5 2.5 0 0 1-3 2.4V2.5z" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/><path d="M8 2.5v10" stroke="currentColor" stroke-width="1.3"/>'),
    "embedding": ("Embeddings (vectors)", '<circle cx="4" cy="4" r="1.4" fill="currentColor"/><circle cx="8" cy="4" r="1.4" fill="currentColor"/><circle cx="12" cy="4" r="1.4" fill="currentColor"/><circle cx="4" cy="8" r="1.4" fill="currentColor"/><circle cx="8" cy="8" r="1.4" fill="currentColor"/><circle cx="12" cy="8" r="1.4" fill="currentColor"/><circle cx="4" cy="12" r="1.4" fill="currentColor"/><circle cx="8" cy="12" r="1.4" fill="currentColor"/><circle cx="12" cy="12" r="1.4" fill="currentColor"/>'),
    "completion": ("Text completion / chat", '<path d="M2.5 3.5h11v7h-6l-3 2.5v-2.5h-2z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/>'),
}


def cap_icons(caps: list[str]) -> str:
    out = []
    for c in caps:
        title, body = CAP_ICONS.get(c, (c, '<circle cx="8" cy="8" r="3" fill="currentColor"/>'))
        out.append(f'<span class="cap{" hi" if c == "tools" else ""}" title="{esc(title)}" aria-label="{esc(title)}"><svg viewBox="0 0 16 16" width="15" height="15">{body}</svg></span>')
    return "".join(out)


def provider_for(name: str) -> str:
    """Native chat API (real tool calls) when the model supports tools; generate API otherwise."""
    return "ollama_chat" if "tools" in model_caps(name) else "ollama"


def installed_models() -> list[dict]:
    st, j = http("GET", OLLAMA + "/api/tags", timeout=10)
    models = j.get("models", []) if isinstance(j, dict) else []
    st2, ps = http("GET", OLLAMA + "/api/ps", timeout=10)
    loaded = {m.get("name"): m for m in (ps.get("models", []) if isinstance(ps, dict) else [])}
    for m in models:
        m["loaded"] = m.get("name") in loaded
        m["vram"] = loaded.get(m.get("name"), {}).get("size_vram", 0)
        m["is_guard"] = is_guard_name(m.get("name") or "")
        m["caps"] = model_caps(m.get("name") or "")
    return sorted(models, key=lambda m: m.get("name", ""))


GUARD_NAME_RE = re.compile(r"guard|shield|guardian", re.I)


def is_guard_name(n: str) -> bool:
    return bool(GUARD_NAME_RE.search(n or ""))


def activate_guard(model: str) -> None:
    """Make the policy's classifier resident and drop other guard models (one selection, one residency)."""
    def run():
        for m in installed_models():
            if m["is_guard"] and m["loaded"] and m["name"] != model:
                http("POST", OLLAMA + "/api/generate", {"model": m["name"], "keep_alive": 0}, timeout=120)
        st, j = http("POST", OLLAMA + "/api/generate", {"model": model, "keep_alive": "24h"}, timeout=900)
        audit("guard_loaded" if st == 200 else "guard_load_failed", model=model, status=st)
    threading.Thread(target=run, daemon=True).start()


def exposed_models() -> list[dict]:
    st, j = litellm("GET", "/model/info")
    return j.get("data", []) if isinstance(j, dict) else []


def current_domain() -> str | None:
    try:
        with open(DOMAIN_FILE, encoding="utf-8") as f:
            for line in f:
                m = re.match(r"^([a-z0-9.-]+) \{$", line.strip())
                if m:
                    return m.group(1)
    except FileNotFoundError:
        pass
    return None


def caddy_reload() -> tuple[bool, str]:
    try:
        with open(CADDYFILE, "rb") as f:
            body = f.read()
    except OSError as e:
        return False, f"cannot read Caddyfile: {e}"
    req = urllib.request.Request(f"{CADDY_ADMIN}/load", data=body, method="POST", headers={"Content-Type": "text/caddyfile", "Origin": "http://127.0.0.1:2019"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return True, f"caddy reloaded ({r.status})"
    except urllib.error.HTTPError as e:
        return False, f"caddy rejected config: {e.read().decode(errors='replace')[:400]}"
    except Exception as e:  # noqa: BLE001
        return False, f"caddy admin unreachable: {e}"


def probe_cert(host, sni=None, port=443) -> dict:
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=5) as s, ctx.wrap_socket(s, server_hostname=sni or host) as tls:
            pem = ssl.DER_cert_to_PEM_cert(tls.getpeercert(binary_form=True))
    except Exception as e:  # noqa: BLE001
        return {"host": sni or host, "error": str(e)}
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(pem); path = f.name
    try:
        d = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    finally:
        os.unlink(path)
    exp = datetime.strptime(d["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    return {"host": sni or host, "issuer": dict(x[0] for x in d.get("issuer", ())).get("commonName", "?"),
            "san": [v for k, v in d.get("subjectAltName", ()) if k == "DNS"], "not_after": d["notAfter"],
            "days": round((exp - datetime.now(timezone.utc)).total_seconds() / 86400, 1)}


def container_status() -> dict:
    d = load_json(OPS_STATUS, {})
    return d.get("containers", {}), d.get("ts", "")


def ops_responses(n=200) -> list[dict]:
    out = []
    try:
        names = sorted((f for f in os.listdir(OPS_RESP) if f.endswith(".json") and f != "status.json"), reverse=True)[:n]
    except OSError:
        return []
    for f in names:
        d = load_json(os.path.join(OPS_RESP, f), None)
        if d:
            d["_file"] = f; out.append(d)
    return out


def pull_job(model: str) -> str:
    jid = secrets.token_hex(4)
    with JOBS_LOCK:
        JOBS[jid] = {"model": model, "status": "starting", "completed": 0, "total": 0, "started": now(), "done": False}
    def run():
        req = urllib.request.Request(MODELD + "/api/pull", data=json.dumps({"name": model, "stream": True}).encode(), headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=3600) as r:
                for line in r:
                    try: d = json.loads(line)
                    except ValueError: continue
                    with JOBS_LOCK:
                        JOBS[jid].update({"status": d.get("status", ""), "completed": d.get("completed", JOBS[jid]["completed"]), "total": d.get("total", JOBS[jid]["total"])})
                        if d.get("error"):
                            JOBS[jid].update({"status": "error: " + d["error"], "done": True}); return
            with JOBS_LOCK:
                JOBS[jid].update({"status": "complete", "done": True})
            audit("model_pull_complete", model=model)
        except Exception as e:  # noqa: BLE001
            with JOBS_LOCK:
                JOBS[jid].update({"status": f"error: {e}", "done": True})
            audit("model_pull_failed", model=model, error=str(e)[:200])
    threading.Thread(target=run, daemon=True).start()
    audit("model_pull_started", model=model, job=jid)
    return jid


def _veto_watcher():
    pos = None
    while True:
        try:
            with open(VETO_AUDIT, encoding="utf-8") as f:
                if pos is None:
                    f.seek(0, 2); pos = f.tell()
                else:
                    f.seek(pos)
                    for line in f:
                        try: e = json.loads(line)
                        except ValueError: continue
                        d, r = str(e.get("detail", "")), str(e.get("reason", ""))
                        if any(k in d or k in r for k in ALERT_ON) and "sentinel" not in r and "sentinel" not in d:
                            alert(f"[aegis-veto] {e.get('stage')} {r} {d} key={e.get('key_alias')} model={e.get('model')} at {e.get('ts', '')[:19]}")
                    pos = f.tell()
        except FileNotFoundError:
            pos = None
        except OSError:
            pass
        time.sleep(3)


# ---------------------------------------------------------------- HTML ---------------------
CSS = """
:root{--bg:#171717;--side:#0d0d0d;--card:#1f1f1f;--line:#2e2e2e;--fg:#ececec;--mut:#9a9a9a;--ok:#22c55e;--warn:#f59e0b;--bad:#ef4444;--acc:#ececec}
*{box-sizing:border-box}html,body{height:100%}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Inter,"Segoe UI",system-ui,sans-serif}
a{color:inherit}.wrap{display:flex;height:100vh;height:100dvh;overflow:hidden}
nav{width:232px;flex:none;background:var(--side);border-right:1px solid var(--line);padding:18px 12px;overflow-y:auto;overscroll-behavior:contain;scrollbar-width:none;-ms-overflow-style:none;-webkit-overflow-scrolling:touch;display:flex;flex-direction:column}nav::-webkit-scrollbar{display:none}
nav .brand{font-weight:600;font-size:16px;padding:6px 10px 16px;letter-spacing:.2px}
nav details{margin:2px 0}nav summary{list-style:none;cursor:pointer;color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.08em;padding:10px 10px 4px;user-select:none;display:flex;justify-content:space-between;align-items:center}
nav summary::-webkit-details-marker{display:none}nav summary::after{content:"+";font-size:13px;color:#666}nav details[open] summary::after{content:"–"}nav details[open] summary{color:#ddd}
nav a{display:block;padding:7px 10px 7px 14px;border-radius:8px;text-decoration:none;color:#cfcfcf}nav a:hover{background:#1a1a1a}nav a.on{background:#262626;color:#fff}
nav .foot{margin-top:auto;padding:12px 10px 0;font-size:12px;color:var(--mut)}
main{flex:1;min-width:0;overflow-y:auto;padding:26px 34px}main>.inner{max-width:1180px}
h1{font-size:20px;font-weight:600;margin:0 0 4px}h2{font-size:15px;font-weight:600;margin:22px 0 8px}
.sub{color:var(--mut);margin:0 0 18px}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:12px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mut);font-weight:500;font-size:12px}
.card table{display:block;overflow-x:auto}
.tag{display:inline-block;font-size:11px;padding:2px 8px;border-radius:999px;background:#2a2a2a;color:#ddd}.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}.mut{color:var(--mut)}
input,select,textarea{background:#111;color:var(--fg);border:1px solid #3a3a3a;border-radius:8px;padding:8px 10px;font:inherit;width:100%;max-width:520px}
input[type=checkbox]{width:auto}textarea{min-height:90px;font-family:ui-monospace,Menlo,monospace;font-size:12px}
button{background:var(--acc);color:#111;border:0;border-radius:8px;padding:8px 14px;font:inherit;font-weight:600;cursor:pointer}button:disabled{opacity:.4;cursor:not-allowed}
button.ghost{background:#2a2a2a;color:#eee}button.danger{background:var(--bad);color:#fff}
form.inline{display:inline}label{display:block;margin:10px 0 4px;color:#ccc}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:end}
pre{background:#0d0d0d;border:1px solid var(--line);border-radius:10px;padding:12px;overflow:auto;font-size:12px;max-height:520px}
.msg{padding:10px 14px;border-radius:10px;margin:0 0 14px;background:#1c2a1c;border:1px solid #2f5a2f}.msg.bad{background:#2a1c1c;border-color:#5a2f2f}
.pager{display:flex;gap:18px;flex-wrap:wrap;align-items:center;justify-content:space-between;margin:8px 0 2px;font-size:12px;color:#bbb}.pager a{padding:2px 7px;border-radius:6px;background:#2a2a2a;text-decoration:none;margin:0 1px}.pager a.on{background:#3a3a3a;color:#fff}
.cap{display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:6px;background:#2a2a2a;color:#cfcfcf;margin-left:3px;vertical-align:middle;cursor:default}.cap.hi{color:var(--ok);background:#1c2a1c}
.lock{opacity:.6}.key{font-family:ui-monospace,monospace;background:#0d0d0d;padding:6px 10px;border-radius:8px;display:inline-block;user-select:all;word-break:break-all}
.login{max-width:380px;margin:12vh auto;padding:0 16px}.login .card{padding:24px}
@media (max-width:760px){.wrap{flex-direction:column;height:auto;overflow:visible}nav{width:auto;border-right:0;border-bottom:1px solid var(--line);overflow:visible}main{overflow:visible;padding:18px 16px}}
"""


def page(section, sub, title, subtitle, body, msg="", ok=True):
    nav = ['<div class="brand">Aegis</div>']
    for sid, sname, subs in NAV:
        links = "".join(f'<a class="{"on" if (sid, ssid) == (section, sub) else ""}" href="/hub/{sid}/{ssid}">{esc(ssname)}</a>' for ssid, ssname in subs)
        nav.append(f'<details{" open" if sid == section else ""}><summary>{esc(sname)}</summary>{links}</details>')
    apps = '<a href="/">Open WebUI ↗</a>' + ('<a href="/grafana/">Grafana ↗</a>' if GRAFANA_ENABLED else '')
    nav.append(f'<details><summary>Apps</summary>{apps}</details>')
    nav.append(f'<div class="foot">{esc(getattr(REQ, "user", ""))} · <a href="/hub/logout">sign out</a></div>')
    m = f'<div class="msg{"" if ok else " bad"}">{esc(msg)}</div>' if msg else ""
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aegis Hub — {esc(title)}</title><style>{CSS}</style></head><body><div class="wrap"><nav>{''.join(nav)}</nav>
<main><div class="inner"><h1>{esc(title)}</h1><p class="sub">{esc(subtitle)}</p>{m}{body}</div></main></div></body></html>"""


def plain_page(title, body, msg="", ok=True):
    m = f'<div class="msg{"" if ok else " bad"}">{esc(msg)}</div>' if msg else ""
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Aegis Hub — {esc(title)}</title><style>{CSS}</style></head>
<body><div class="login"><div class="card"><h1 style="margin-bottom:14px">{esc(title)}</h1>{m}{body}</div></div></body></html>"""


def csrf_field():
    return f'<input type="hidden" name="csrf" value="{CSRF}">'


# ---------------------------------------------------------------- auth pages ---------------
def p_setup(msg="", ok=True):
    body = ("<p class=\"mut\">No administrator exists yet. Create the administrator account now; you will then enroll a second factor. "
            "Passwords are stored only as argon2id hashes.</p>"
            "<form method=\"post\" action=\"/hub/setup\">" + csrf_field() +
            "<label>Administrator username</label><input name=\"user\" value=\"admin\" pattern=\"[a-z0-9][a-z0-9._-]+\" required autofocus>"
            "<label>Password</label><input name=\"password\" type=\"password\" autocomplete=\"new-password\" required minlength=\"14\">"
            "<label>Confirm password</label><input name=\"confirm\" type=\"password\" autocomplete=\"new-password\" required minlength=\"14\">"
            "<div class=\"mut\" style=\"margin-top:6px\">At least 14 characters; three of lowercase, uppercase, digit, symbol; no spaces; "
            "not containing &quot;admin&quot;, &quot;aegis&quot; or &quot;password&quot;.</div>"
            "<div style=\"margin-top:14px\"><button>Create administrator and continue to MFA</button></div></form>")
    return plain_page("First-run setup", body, msg, ok)


def p_login(msg="", ok=True):
    return plain_page("Sign in", f'<form method="post" action="/hub/login">{csrf_field()}<label>Username</label><input name="user" autocomplete="username" required autofocus><label>Password</label><input name="password" type="password" autocomplete="current-password" required><div style="margin-top:14px"><button>Continue</button></div></form>', msg, ok)


def p_totp(pre: str, msg="", ok=True):
    return plain_page("Second factor", f'<form method="post" action="/hub/login/totp">{csrf_field()}<input type="hidden" name="pre" value="{esc(pre)}"><label>Authenticator code</label><input name="code" inputmode="numeric" pattern="[0-9 ]*" autocomplete="one-time-code" required autofocus><div style="margin-top:14px"><button>Sign in</button></div></form>', msg, ok)


def qr_svg(data: str) -> str:
    import qrcode
    import qrcode.image.svg as svg
    img = qrcode.make(data, image_factory=svg.SvgPathImage, box_size=10, border=2, error_correction=qrcode.constants.ERROR_CORRECT_M)
    raw = img.to_string().decode() if isinstance(img.to_string(), bytes) else img.to_string()
    raw = re.sub(r"<\?xml[^>]*>", "", raw)
    return re.sub(r"<svg ", '<svg style="width:220px;height:220px;background:#fff;border-radius:10px;padding:8px" ', raw, 1)


def p_enrol(pre: str, secret: str, user: str, msg="", ok=True):
    uri = f"otpauth://totp/Aegis%20Hub:{urllib.parse.quote(user)}?secret={secret}&issuer=Aegis%20Hub&algorithm=SHA1&digits=6&period=30"
    return plain_page("Enroll MFA", f'''<p class="mut">Scan this with Google Authenticator, Authy, 1Password or any TOTP app, then enter the 6-digit code it shows. MFA is mandatory.</p>
<div style="text-align:center;margin:10px 0">{qr_svg(uri)}</div>
<details><summary class="mut">Can't scan? Manual entry</summary><label>Account</label><div class="key">Aegis Hub:{esc(user)}</div><label>Key (base32, time-based, 6 digits, 30 s)</label><div class="key">{esc(" ".join(secret[i:i + 4] for i in range(0, len(secret), 4)))}</div></details>
<form method="post" action="/hub/login/enrol">{csrf_field()}<input type="hidden" name="pre" value="{esc(pre)}"><input type="hidden" name="secret" value="{esc(secret)}"><label>Code from the app</label><input name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus><div style="margin-top:14px"><button>Confirm and sign in</button></div></form>''', msg, ok)


def p_force_password(msg="", ok=True):
    return plain_page("Set a new password", f'<p class="mut">This account is using a bootstrap password. Choose your own before continuing.</p><form method="post" action="/hub/account/password">{csrf_field()}<input type="hidden" name="forced" value="1"><label>Current (bootstrap) password</label><input name="current" type="password" required><label>New password</label><input name="new" type="password" required minlength="14"><label>Confirm</label><input name="confirm" type="password" required minlength="14"><div class="mut" style="margin-top:6px">≥ 14 chars; 3 of 4 classes; no spaces; no "admin"/"aegis"/"password".</div><div style="margin-top:14px"><button>Save</button></div></form>', msg, ok)


# ---------------------------------------------------------------- pages --------------------
def p_dashboard(msg="", ok=True):
    pol = policy(); blocked = sorted(c for c, v in pol["categories"].items() if v.get("block"))
    cst, cts = container_status()
    tiles = "".join(f'<div class="card"><b>{esc(n)}</b> <span class="tag">{esc(SERVICES.get(n, ("", "", False))[1])}</span><div class="{"ok" if s.get("status") == "running" and s.get("health") in ("", "healthy") else ("mut" if s.get("status") == "absent" else "bad")}">{esc(s.get("status"))} {esc(s.get("health"))}</div></div>' for n, s in cst.items() if s.get("status") != "absent") or '<div class="card mut">watchdog status not available — is aegis-watchdog running on the host?</div>'
    models = installed_models(); loaded = [m for m in models if m["loaded"]]
    vram = ", ".join(f'{esc(m["name"])} ({m["vram"] / 2**30:.1f} GiB VRAM)' for m in loaded) or "nothing resident"
    if loaded and all(m["vram"] == 0 for m in loaded):
        vram += ' <span class="bad">— resident models have 0 VRAM: the inference container has lost its GPUs. Restart ollama from Services.</span>'
        if not msg:
            msg, ok = "GPU residency lost — inference is running on CPU. Restart ollama from Services.", False
    certs = [probe_cert(LAN_IP)] + ([probe_cert(LAN_IP, current_domain())] if current_domain() else [])
    certrows = "".join(f'<tr><td>{esc(c["host"])}</td><td>{esc(c.get("issuer", c.get("error")))}</td><td class="{"warn" if c.get("days", 99) < 14 else "ok"}">{c.get("days", "—")}</td></tr>' for c in certs)
    events = tail_jsonl(VETO_AUDIT, 8)
    evrows = "".join(f'<tr><td class="mut">{esc(e.get("ts", "")[:19])}</td><td>{esc(e.get("stage"))}</td><td>{esc(e.get("reason"))}</td><td>{esc(e.get("detail", ""))[:70]}</td><td>{esc(e.get("key_alias"))}</td></tr>' for e in events) or '<tr><td colspan="5" class="mut">no vetoes recorded</td></tr>'
    g = pol["guard"]["model"]; g_inst = any(m["name"] == g for m in models); g_res = any(m["name"] == g and m["loaded"] for m in models)
    gtag = f'<span class="tag">{esc(g)}</span> ' + ('<span class="bad">NOT INSTALLED — all requests refused</span>' if not g_inst else ('<span class="ok">resident</span>' if g_res else '<span class="warn">not resident (loads on next request)</span>'))
    body = f"""<div class="grid">{tiles}</div><p class="mut">Container status via host watchdog · {esc(cts[:19])}</p>
<div class="card"><h2 style="margin-top:0">Safety posture</h2>Classifier {gtag} · blocking {len(blocked)} categories: {esc(", ".join(blocked))} · tripwires {"on" if pol["tripwires"].get("enabled") else "OFF"} · <b>fail-closed</b> · streaming buffered · snippets {"ON" if pol.get("audit", {}).get("store_snippet") else "off"}
<div class="mut" style="margin-top:6px">Resident in VRAM: {vram}</div></div>
<div class="card"><h2 style="margin-top:0">Certificates</h2><table><tr><th>Host</th><th>Issuer</th><th>Days left</th></tr>{certrows}</table></div>
<div class="card"><h2 style="margin-top:0">Recent vetoes</h2><table><tr><th>Time</th><th>Stage</th><th>Reason</th><th>Detail</th><th>Key</th></tr>{evrows}</table></div>"""
    return page("overview", "dashboard", "Dashboard", "Live state of the platform. Nothing here is editable.", body, msg, ok)


def p_services(msg="", ok=True):
    cst, cts = container_status()
    pending = os.path.exists(OPS_REQ)
    resp = ops_responses(500)
    last: dict[str, str] = {}
    for r in resp:
        for t in (r.get("request", {}).get("targets") or []):
            names = list(SERVICES) if t == "*" else [t]
            for n in names:
                if n not in last:
                    errs = [e for e in r.get("errors", []) if n in e]
                    last[n] = ("ok" if r.get("ok") else ("error: " + "; ".join(errs)[:80] if errs else "error (see responses)")) + f' <span class="mut">{esc(r.get("completed", "")[:19])}</span>'
    rows = ""
    for n, (purpose, net, prot) in SERVICES.items():
        s = cst.get(n, {"status": "unknown", "health": ""})
        cls = "ok" if s.get("status") == "running" and s.get("health") in ("", "healthy") else ("mut" if s.get("status") in ("absent", "unknown") else "bad")
        rows += f'<tr><td><input type="checkbox" name="t" value="{esc(n)}" form="ops"></td><td>{esc(n)}{" <span class=tag>protected</span>" if prot else ""}</td><td class="{cls}">{esc(s.get("status"))} {esc(s.get("health"))}</td><td class="mut">{esc(purpose)}</td><td>{last.get(n, "<span class=mut>—</span>")}</td></tr>'
    dis = "disabled" if pending else ""
    body = f"""<form method="post" action="/hub/api/ops" id="ops">{csrf_field()}<div class="card"><div class="row"><button name="action" value="start" {dis}>Start</button><button name="action" value="stop" class="danger" {dis}>Stop</button><button name="action" value="restart" class="ghost" {dis}>Restart</button>
<span class="mut">{"a request is in progress — wait for the response" if pending else "applies to the checked containers · caddy and hub can only be restarted"}</span></div></div></form>
<div class="card"><table><tr><th></th><th>Container</th><th>Status</th><th>Purpose</th><th>Last response</th></tr>{rows}</table><p class="mut">Status via host watchdog at {esc(cts[:19])}. Stopping a dependency stops its dependents first; restarting brings them back in order.</p></div>"""
    rr, rctl = paginate(resp, "r", 10)
    rrows = "".join(f'<tr><td class="mut">{esc(r.get("completed", "")[:19])}</td><td>{esc(r.get("request", {}).get("action"))} {esc(",".join(r.get("request", {}).get("targets") or []))}</td><td class="{"ok" if r.get("ok") else "bad"}">{"ok" if r.get("ok") else "failed"}</td><td><details><summary class="mut">{len(r.get("log", []))} steps{", " + str(len(r.get("errors", []))) + " errors" if r.get("errors") else ""}</summary><pre>{esc(chr(10).join(r.get("log", []) + r.get("errors", [])))}</pre></details></td></tr>' for r in rr) or '<tr><td colspan="4" class="mut">no requests yet</td></tr>'
    body += f'<div class="card"><h2 style="margin-top:0">Watchdog responses</h2>{rctl}<table><tr><th>Completed</th><th>Request</th><th>Result</th><th>Log</th></tr>{rrows}</table></div>'
    return page("overview", "services", "Services", "Container control through the host watchdog (no Docker socket in any container).", body, msg, ok)


def p_policy(msg="", ok=True):
    pol = policy(); inst = installed_models(); guards = [m["name"] for m in inst if m["is_guard"]]
    cur = pol["guard"]["model"]; missing = cur not in guards
    resident = any(m["name"] == cur and m["loaded"] for m in inst)
    if missing:
        guards.append(cur)
    opts = "".join(f'<option value="{esc(g)}"{" selected" if g == cur else ""}{"" if has_adapter(g) else " disabled"}>{esc(g)}{" (NOT INSTALLED)" if g == cur and missing else ""}{"" if has_adapter(g) else " — no verdict adapter yet"}</option>' for g in guards)
    gstate = ('<span class="bad">not installed — every request is being refused (fail-closed). Pull it or choose another.</span>' if missing else
              ('<span class="ok">resident in memory</span>' if resident else '<span class="warn">on disk, not resident — loads on the next request (~20 s once)</span>'))
    rows = ""
    for c, (name, kind) in CATEGORIES.items():
        b = pol["categories"][c]["block"]; locked_c = c == "S4"
        rows += f'<tr class="{"lock" if locked_c else ""}"><td><input type="checkbox" name="block_{c}" {"checked" if b else ""} {"disabled" if locked_c else ""}></td><td>{c}</td><td>{esc(name)}</td><td><span class="tag">{esc(kind)}</span></td><td class="mut">{"always blocked — cannot be changed" if locked_c else ""}</td></tr>'
    extra = "\n".join(pol["tripwires"].get("extra_patterns", []))
    body = f"""<form method="post" action="/hub/api/policy">{csrf_field()}
<div class="card"><h2 style="margin-top:0">Classifier (Llama Guard 3)</h2><label>Classifier model (installed models named *guard*, *shield* or *guardian*)</label><select name="guard_model">{opts}</select>
<div style="margin-top:6px">Status: {gstate}</div>
<div class="mut" style="margin-top:6px">This is the only place the classifier is chosen. Saving loads it into memory and unloads any other guard model. It runs on every request and every response (streaming buffered), cannot be disabled, and if it is missing or unreachable every request is refused. Load your main model <b>before</b> choosing a larger guard so both fit in VRAM. Verdict adapters decide how a family is asked and how its answer is read; today: Llama Guard (expects "safe" or "unsafe" + S-codes). Recognised families without an adapter (ShieldGemma, Granite Guardian, WildGuard) are listed but cannot be selected. If an answer ever fails to parse, the request is refused and the audit log records what came back and what was expected.</div></div>
<div class="card"><h2 style="margin-top:0">Blocked categories</h2><table><tr><th>Block</th><th>Code</th><th>Category</th><th>Class</th><th></th></tr>{rows}</table><div class="mut">Illegal and protected-class content never passes; adult content may. Unchecking an "illegal" class is allowed but audited and alerted.</div></div>
<div class="card"><h2 style="margin-top:0">Lexical tripwires</h2><label><input type="checkbox" name="tripwires" {"checked" if pol["tripwires"].get("enabled", True) else ""}> Enabled (built-in lists for sentinel / CSAM terms / malware intent)</label><label>Extra patterns — one Python regex per line</label><textarea name="extra">{esc(extra)}</textarea></div>
<div class="card"><h2 style="margin-top:0">Diagnostics</h2><label><input type="checkbox" name="store_snippet" {"checked" if pol.get("audit", {}).get("store_snippet") else ""}> Store a 160-character snippet of <b>flagged output</b> (root-only file)</label><div class="mut">Off by default: logs never contain content. Never applies to S4 or CSAM-tripwire vetoes. Toggling is audited and alerted.</div></div>
<p class="mut">Last change: {esc(pol.get("updated") or "never")} by {esc(pol.get("updated_by") or "—")}.</p><button type="submit">Save policy</button></form>"""
    return page("safety", "policy", "VetoGuard policy", "What the safety gate blocks. Administrator only; every change is audited.", body, msg, ok)


def p_audit():
    snips = tail_jsonl(SNIPPETS, 500); srows = ""
    if snips:
        sp, sctl = paginate(snips, "n")
        srows = '<div class="card"><h2 style="margin-top:0">Flagged-output snippets (diagnostics)</h2>' + sctl + '<table><tr><th>Time</th><th>Stage</th><th>Reason</th><th>Key</th><th>Snippet</th></tr>' + "".join(f'<tr><td class="mut">{esc(e.get("ts", "")[:19])}</td><td>{esc(e.get("stage"))}</td><td>{esc(e.get("reason"))} {esc(e.get("detail", ""))}</td><td>{esc(e.get("key_alias"))}</td><td><code>{esc(e.get("snippet", ""))}</code></td></tr>' for e in sp) + '</table></div>'
    veto, vctl = paginate(tail_jsonl(VETO_AUDIT, 5000), "v"); hub, hctl = paginate(tail_jsonl(HUB_AUDIT, 5000), "h")
    vrows = "".join(f'<tr><td class="mut">{esc(e.get("ts", "")[:19])}</td><td>{esc(e.get("stage"))}</td><td>{esc(e.get("reason"))}</td><td>{esc(e.get("detail", ""))[:90]}</td><td>{esc(e.get("model"))}</td><td>{esc(e.get("key_alias"))}</td></tr>' for e in veto) or '<tr><td colspan="6" class="mut">none</td></tr>'
    hrows = "".join(f'<tr><td class="mut">{esc(e.get("ts", "")[:19])}</td><td>{esc(e.get("actor"))}</td><td>{esc(e.get("event"))}</td><td>{esc(", ".join(f"{k}={v}" for k, v in e.items() if k not in ("ts", "event", "actor")))[:120]}</td></tr>' for e in hub) or '<tr><td colspan="4" class="mut">none</td></tr>'
    body = srows + f'<div class="card"><h2 style="margin-top:0">Vetoes</h2>{vctl}<table><tr><th>Time</th><th>Stage</th><th>Reason</th><th>Category / detail</th><th>Model</th><th>Key</th></tr>{vrows}</table>{vctl}</div><div class="card"><h2 style="margin-top:0">Admin actions</h2>{hctl}<table><tr><th>Time</th><th>Actor</th><th>Event</th><th>Fields</th></tr>{hrows}</table>{hctl}</div><p class="mut">Logs never contain message content. Files: proxy/audit/veto-audit.jsonl, proxy/audit/hub-audit.jsonl (root-only on the host).</p>'
    return page("safety", "audit", "Audit log", "Every veto (what tripped, who, when) and every administrative action.", body)


def p_alerts(msg="", ok=True):
    body = f"""<form method="post" action="/hub/api/alerts">{csrf_field()}<div class="card"><label>Webhook URL (Discord, Slack, or any endpoint accepting JSON POST)</label><input name="webhook" value="{esc(state().get("webhook", ""))}" placeholder="https://…">
<div class="mut" style="margin-top:6px">Every admin action and every illegal/protected-class veto (S1–S4, S9–S11, CSAM/malware/extra tripwires) is posted here — codes, names, key alias and time only. Leave blank to disable.</div>
<div class="row" style="margin-top:12px"><button name="action" value="save">Save</button><button class="ghost" name="action" value="test">Send test</button></div></div></form>"""
    return page("safety", "alerts", "Alerts", "Where administrative and safety events are pushed.", body, msg, ok)


def p_installed(msg="", ok=True):
    exposed = {m.get("litellm_params", {}).get("model", "").replace("ollama/", ""): m.get("model_name") for m in exposed_models()}
    rows = ""; models, mctl = paginate(installed_models(), "m")
    for m in models:
        n = m["name"]; size = m.get("size", 0) / 2**30
        exp = exposed.get(n) or exposed.get(n.replace(":latest", ""))
        act = (f'<span class="tag ok">active classifier</span>' if n == policy()["guard"]["model"] else
                f'<form class="inline" method="post" action="/hub/api/models/setguard">{csrf_field()}<input type="hidden" name="model" value="{esc(n)}"><button class="ghost">Set as classifier</button></form>') if m["is_guard"] else (f'<span class="tag ok">exposed as {esc(exp)}</span>' if exp else f'<form class="inline" method="post" action="/hub/api/models/expose">{csrf_field()}<input type="hidden" name="model" value="{esc(n)}"><input name="public" placeholder="public name" style="width:150px" value="{esc(n.split(":")[0].split("/")[-1])}"> <button class="ghost">Expose</button></form>')
        ld = "" if m["is_guard"] else (f'<form class="inline" method="post" action="/hub/api/models/unload">{csrf_field()}<input type="hidden" name="model" value="{esc(n)}"><button class="ghost">Unload</button></form>' if m["loaded"] else f'<form class="inline" method="post" action="/hub/api/models/load">{csrf_field()}<input type="hidden" name="model" value="{esc(n)}"><button class="ghost">Load</button></form>')
        rm = "" if exp or m["loaded"] or n == policy()["guard"]["model"] else f'<form class="inline" method="post" action="/hub/api/models/remove">{csrf_field()}<input type="hidden" name="model" value="{esc(n)}"><input type="hidden" name="confirm" value="{esc(n)}"><button class="danger">Remove</button></form>'
        rows += f'<tr><td>{esc(n)} {cap_icons(m.get("caps", []))}</td><td>{size:.1f} GiB</td><td>{"<span class=ok>resident</span>" if m["loaded"] else "<span class=mut>on disk</span>"}</td><td>{act}</td><td>{ld} {rm}</td></tr>'
    body = f'<div class="card">{mctl}<table><tr><th>Model</th><th>Size</th><th>State</th><th>Exposure</th><th></th></tr>{rows or "<tr><td colspan=5 class=mut>none</td></tr>"}</table></div><p class="mut">"Expose" registers the model in LiteLLM under a public name (through VetoGuard); models that advertise <b>tools</b> are registered on the native chat API so assistants such as Home Assistant get real tool calls — a model without <b>tools</b> can only answer in text. Guard models are never exposable; the active classifier is chosen in Safety → VetoGuard policy (or "Set as classifier" here — same action) and is loaded/unloaded by that choice, not by hand. Unload before removing.</p>'
    return page("models", "installed", "Installed models", "What is in the shared model store, and what apps can see.", body, msg, ok)


def p_pull(msg="", ok=True):
    with JOBS_LOCK:
        jobs = sorted(JOBS.items(), key=lambda kv: kv[1]["started"], reverse=True)
    jobs, jctl = paginate(jobs, "j", 10)
    rows = "".join(f'<tr><td>{esc(j["model"])}</td><td>{esc(j["status"])}</td><td>{(j["completed"] / j["total"] * 100) if j["total"] else 0:.0f}%</td><td class="mut">{esc(j["started"][:19])}</td></tr>' for _, j in jobs) or '<tr><td colspan="4" class="mut">no pulls yet</td></tr>'
    body = f"""<form method="post" action="/hub/api/models/pull">{csrf_field()}<div class="card"><label>Model to pull (Ollama library name)</label><div class="row"><input name="model" placeholder="name:tag" required pattern="[a-z0-9][a-z0-9._/:-]*"><button>Pull</button></div><div class="mut" style="margin-top:6px">Pulls run through <b>modeld</b>, the only container with both internet access and the model store.</div></div></form>
<div class="card"><h2 style="margin-top:0">Jobs</h2>{jctl}<table><tr><th>Model</th><th>Status</th><th>Progress</th><th>Started</th></tr>{rows}</table><p class="mut">Refresh the page for progress.</p></div>"""
    return page("models", "pull", "Pull a model", "Download into the shared store for every app on the box.", body, msg, ok)


def p_exposed(msg="", ok=True):
    rows = ""; ex, ectl = paginate(exposed_models(), "e")
    for m in ex:
        mid = str(m.get("model_info", {}).get("id", "")); pub = m.get("model_name"); up = m.get("litellm_params", {}).get("model")
        src = "hub" if len(mid) >= 8 and "-" in mid else "config.yaml (console)"
        rm = f'<form class="inline" method="post" action="/hub/api/models/unexpose">{csrf_field()}<input type="hidden" name="id" value="{esc(mid)}"><input type="hidden" name="public" value="{esc(pub)}"><button class="danger">Unexpose</button></form>' if src == "hub" else '<span class="mut">console</span>'
        tools = '<span class="tag ok">tool calls</span>' if str(up).startswith("ollama_chat/") else '<span class="tag">text only</span>'
        rows += f'<tr><td>{esc(pub)}</td><td>{esc(up)} {tools}</td><td>{esc(src)}</td><td>{rm}</td></tr>'
    body = f'<div class="card">{ectl}<table><tr><th>Public name</th><th>Upstream</th><th>Defined in</th><th></th></tr>{rows or "<tr><td colspan=4 class=mut>none</td></tr>"}</table></div>'
    return page("models", "exposed", "Exposed to apps", "Models LiteLLM currently serves — all through VetoGuard.", body, msg, ok)


def p_keys(msg="", ok=True, newkey=None):
    st, j = litellm("GET", "/key/list?return_full_object=true&page=1&size=100")
    keys = [k for k in (j.get("keys", []) if isinstance(j, dict) else []) if k.get("key_alias")]; keys, kctl = paginate(keys, "k")
    pubs = [m.get("model_name") for m in exposed_models()]
    def model_select(k):
        cur = set(k.get("models") or [])
        return "".join(f'<option value="{esc(p)}"{" selected" if p in cur else ""}>{esc(p)}</option>' for p in pubs)
    rows = "".join(f'<tr><td>{esc(k.get("key_alias"))}</td><td><form class="inline" method="post" action="/hub/api/keys/update">{csrf_field()}<input type="hidden" name="alias" value="{esc(k.get("key_alias"))}"><select name="models" multiple size="2" style="width:170px">{model_select(k)}</select> <button class="ghost">Update models</button></form><div class="mut">{esc(", ".join(k.get("models") or []) or "all exposed")}</div></td><td>{esc(k.get("rpm_limit"))}/{esc(k.get("tpm_limit"))}</td><td class="mut">{esc((k.get("created_at") or "")[:19])}</td><td><form class="inline" method="post" action="/hub/api/keys/revoke">{csrf_field()}<input type="hidden" name="alias" value="{esc(k.get("key_alias"))}"><button class="danger">Revoke</button></form></td></tr>' for k in keys) or '<tr><td colspan="5" class="mut">none</td></tr>'
    opts = "".join(f'<option value="{esc(p)}">{esc(p)}</option>' for p in pubs)
    banner = f'<div class="card"><b>New key — shown once, store it now:</b><br><span class="key">{esc(newkey)}</span></div>' if newkey else ""
    body = f"""{banner}<div class="card">{kctl}<table><tr><th>Alias</th><th>Models</th><th>rpm/tpm</th><th>Created</th><th></th></tr>{rows}</table></div>
<form method="post" action="/hub/api/keys/mint">{csrf_field()}<div class="card"><h2 style="margin-top:0">Mint a key</h2><div class="row"><div><label>Alias (client name)</label><input name="alias" required pattern="[a-z0-9][a-z0-9._-]+" placeholder="home-assistant"></div><div><label>Models</label><select name="models" multiple size="3">{opts}</select></div><div><label>rpm</label><input name="rpm" type="number" value="60" min="1" style="width:100px"></div><div><label>tpm</label><input name="tpm" type="number" value="200000" min="1000" style="width:130px"></div><button>Mint</button></div></div></form>"""
    return page("access", "keys", "API keys", "Credentials for other services using the OpenAI-compatible API at /v1.", body, msg, ok)


def p_account(msg="", ok=True):
    u = users().get(getattr(REQ, "user", "admin"), {})
    body = f"""<div class="card"><h2 style="margin-top:0">Password</h2><form method="post" action="/hub/account/password">{csrf_field()}<label>Current password</label><input name="current" type="password" autocomplete="current-password" required><label>New password</label><input name="new" type="password" autocomplete="new-password" required minlength="14"><label>Confirm</label><input name="confirm" type="password" autocomplete="new-password" required minlength="14"><div class="mut" style="margin-top:6px">≥ 14 chars; 3 of 4 classes; no spaces; no "admin"/"aegis"/"password". Stored as argon2id (64 MiB, t=3). Changing it signs out other sessions.</div><div style="margin-top:12px"><button>Change password</button></div></form></div>
<div class="card"><h2 style="margin-top:0">Multi-factor authentication</h2><p>Status: <b class="{"ok" if u.get("totp") else "bad"}">{"enrolled" if u.get("totp") else "NOT enrolled"}</b> · last updated {esc(u.get("updated", ""))[:19]}</p>
<form method="post" action="/hub/account/mfa-reset">{csrf_field()}<label>Current password</label><input name="current" type="password" required><label>Current authenticator code</label><input name="code" inputmode="numeric" required><div style="margin-top:12px"><button class="ghost">Re-enroll MFA (new secret)</button></div></form>
<p class="mut">Lost the authenticator or password? Console only: <code>scripts/hub-reset-admin.sh</code> removes the administrator; the setup wizard then runs again in the browser.</p></div>"""
    return page("access", "account", "Admin account", "Your credential. Passwords are never stored — only argon2id hashes; the TOTP secret is encrypted at rest.", body, msg, ok)


def p_certs():
    dom = current_domain(); certs = [probe_cert(LAN_IP)] + ([probe_cert(LAN_IP, dom)] if dom else [])
    rows = "".join(f'<tr><td>{esc(c["host"])}</td><td>{esc(c.get("issuer", ""))}</td><td>{esc(", ".join(c.get("san", [])))}</td><td>{esc(c.get("not_after", ""))}</td><td class="{"warn" if c.get("days", 99) < 14 else "ok"}">{c.get("days", "")}</td><td class="bad">{esc(c.get("error", ""))}</td></tr>' for c in certs)
    body = f'<div class="card"><table><tr><th>Host</th><th>Issuer</th><th>SANs</th><th>Expires</th><th>Days</th><th></th></tr>{rows}</table></div><p class="mut">Caddy renews automatically at two-thirds of lifetime.</p>'
    return page("gateway", "certs", "Certificates", "Live TLS state of every endpoint Caddy serves.", body)


def p_hostname(msg="", ok=True):
    dom = current_domain()
    body = f"""<form method="post" action="/hub/api/hostname">{csrf_field()}<div class="card"><h2 style="margin-top:0">Public hostname via Cloudflare DNS-01</h2><p class="mut">The box stays private. Caddy proves ownership with a scoped Cloudflare token and obtains a Let's Encrypt certificate. No inbound ports.</p>
<label>Hostname</label><input name="hostname" value="{esc(dom or "")}" placeholder="ai.example.com" pattern="[a-z0-9.-]+"><label>Cloudflare API token (leave blank to keep the stored one)</label><input name="token" type="password" autocomplete="off">
<div class="row" style="margin-top:12px"><button name="action" value="apply">Apply</button><button class="danger" name="action" value="remove" formnovalidate>Remove hostname</button></div><div class="mut" style="margin-top:8px">Current: <b>{esc(dom or "none")}</b>.</div></div></form>"""
    return page("gateway", "hostname", "Public hostname", "The one piece of Caddy configuration the hub may write.", body, msg, ok)


def p_isolation():
    try: cf = open(CADDYFILE, encoding="utf-8").read()
    except OSError as e: cf = f"(unreadable: {e})"
    try: comp = open(COMPOSE_VIEW, encoding="utf-8").read()
    except OSError as e: comp = f"(unreadable: {e})"
    nets = "\n".join(l for l in comp.splitlines() if re.match(r"^(networks:|  [a-z0-9_-]+:$|    networks:|    network_mode|      internal:|    ports:)", l) or re.match(r"^    - \"\d", l))
    body = f'<p class="mut">This is the isolation layer. Shown so you can verify it; changing it requires the console and root.</p><div class="card"><h2 style="margin-top:0">caddy/Caddyfile</h2><pre>{esc(cf)}</pre></div><div class="card"><h2 style="margin-top:0">docker-compose.yml — network wiring</h2><pre>{esc(nets)}</pre><details><summary class="mut">full compose file</summary><pre>{esc(comp)}</pre></details></div>'
    return page("gateway", "isolation", "Isolation (read-only)", "Interconnects, routes, auth and capabilities — view only.", body)


# ---------------------------------------------------------------- actions ------------------
def act_ops(form):
    action = form.get("action", ""); targets = [t for t in form.getlist("t") if t in SERVICES]
    if action not in ("start", "stop", "restart"):
        return p_services("Unknown action.", False)
    if not targets:
        return p_services("Select at least one container.", False)
    prot = [t for t in targets if SERVICES[t][2]]
    if action == "stop" and prot:
        return p_services(f"{', '.join(prot)} can only be restarted, never stopped.", False)
    if os.path.exists(OPS_REQ):
        return p_services("A request is already pending. Wait for the watchdog response.", False)
    rid = secrets.token_hex(4)
    req = {"id": rid, "ts": now(), "action": action, "targets": targets, "requested_by": getattr(REQ, "user", "admin")}
    tmp = OPS_REQ + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(req, f)
        os.replace(tmp, OPS_REQ)
    except OSError as e:
        return p_services(f"Could not write the request: {e}", False)
    audit("ops_request", action=action, targets=",".join(targets), id=rid)
    return p_services(f"Requested {action} of {', '.join(targets)} (id {rid}). The watchdog will answer below; refresh in a few seconds.")


def act_policy(form):
    pol = policy(); before = {c: v["block"] for c, v in pol["categories"].items()}; before_model = pol["guard"]["model"]
    gm = form.get("guard_model", pol["guard"]["model"])
    if not MODEL_RE.match(gm) or not is_guard_name(gm):
        return p_policy("Classifier must be an installed model named *guard*, *shield* or *guardian*.", False)
    if gm not in [m["name"] for m in installed_models()]:
        return p_policy(f"{gm} is not installed. Pull it first (Models → Pull).", False)
    if not has_adapter(gm):
        return p_policy(f"{gm} has no verdict adapter yet; selecting it would refuse every request. Adapters: Llama Guard.", False)
    for c in CATEGORIES:
        pol["categories"][c]["block"] = (f"block_{c}" in form) or c == "S4"
    extra = [l.strip() for l in form.get("extra", "").splitlines() if l.strip()]
    for pat in extra:
        try: re.compile(pat)
        except re.error as e: return p_policy(f"Invalid regex {pat!r}: {e}", False)
    pol["guard"]["model"] = gm; pol["tripwires"] = {"enabled": "tripwires" in form, "extra_patterns": extra}
    snip = "store_snippet" in form
    if snip != bool(pol.get("audit", {}).get("store_snippet")):
        audit("snippet_logging_" + ("enabled" if snip else "disabled"))
    pol["audit"] = {"store_snippet": snip}; pol["updated"], pol["updated_by"] = now(), getattr(REQ, "user", "admin")
    save_json(POLICY_FILE, pol)
    changed = [f"{c}:{'block' if pol['categories'][c]['block'] else 'allow'}" for c in CATEGORIES if before[c] != pol["categories"][c]["block"]]
    audit("policy_saved", guard_model=gm, changed=",".join(changed) or "none", tripwires=pol["tripwires"]["enabled"], extra_patterns=len(extra))
    if gm != before_model:
        activate_guard(gm)
        return p_policy(f"Policy saved. Loading {gm} into memory now (other guard models are being unloaded); refresh in ~20 s to see it resident.")
    return p_policy("Policy saved. LiteLLM picks it up within seconds (no restart).")


def act_alerts(form):
    s = state()
    if form.get("action") == "test":
        alert("test alert from Aegis Hub"); return p_alerts("Test sent (if a webhook is configured).")
    url = form.get("webhook", "").strip()
    if url and not url.startswith("https://"):
        return p_alerts("Webhook must be an https:// URL.", False)
    s["webhook"] = url; save_json(STATE_FILE, s); audit("alerts_webhook_set", configured=bool(url))
    return p_alerts("Saved.")


def act_pull(form):
    m = form.get("model", "").strip().lower()
    if not MODEL_RE.match(m):
        return p_pull("Invalid model name.", False)
    pull_job(m); return p_pull(f"Pull started for {m}.")


def act_expose(form):
    m, pub = form.get("model", "").strip(), form.get("public", "").strip().lower()
    if not MODEL_RE.match(m) or "guard" in m.lower():
        return p_installed("Guard models cannot be exposed.", False)
    if not ALIAS_RE.match(pub):
        return p_installed("Public name must be lowercase letters, digits, dot, dash, underscore.", False)
    prov = provider_for(m)
    st, j = litellm("POST", "/model/new", {"model_name": pub, "litellm_params": {"model": f"{prov}/{m}", "api_base": OLLAMA}}); ok = st == 200
    audit("model_exposed" if ok else "model_expose_failed", model=m, public=pub, provider=prov, tools="tools" in model_caps(m), status=st)
    return p_installed((f"Exposed {m} as {pub} (native tool calls)." if prov == "ollama_chat" else f"Exposed {m} as {pub}. Note: this model does not support tool calling; assistants that send tools will get text, not actions.") if ok else f"LiteLLM refused ({st}): {str(j)[:200]}", ok)


def act_unexpose(form):
    mid, pub = form.get("id", ""), form.get("public", "")
    st, j = litellm("POST", "/model/delete", {"id": mid}); ok = st == 200
    audit("model_unexposed" if ok else "model_unexpose_failed", public=pub, status=st)
    return p_exposed(f"Unexposed {pub}." if ok else f"LiteLLM refused ({st}).", ok)


def act_setguard(form):
    m = form.get("model", "")
    if not MODEL_RE.match(m) or not is_guard_name(m) or m not in [x["name"] for x in installed_models()]:
        return p_installed("Not an installed guard-family model.", False)
    if not has_adapter(m):
        return p_installed(f"{m} has no verdict adapter yet (roadmap #11); it cannot be the classifier.", False)
    pol = policy(); prev = pol["guard"]["model"]; pol["guard"]["model"] = m; pol["updated"], pol["updated_by"] = now(), getattr(REQ, "user", "admin")
    save_json(POLICY_FILE, pol); audit("policy_saved", guard_model=m, changed="none", tripwires=pol["tripwires"]["enabled"], extra_patterns=len(pol["tripwires"].get("extra_patterns", [])))
    if m != prev:
        activate_guard(m)
    return p_installed(f"{m} is now the classifier and is being loaded; the previous guard is being unloaded.")


def act_unload(form):
    m = form.get("model", "")
    if not MODEL_RE.match(m): return p_installed("Invalid model name.", False)
    st, j = http("POST", OLLAMA + "/api/generate", {"model": m, "keep_alive": 0}, timeout=120); ok = st == 200
    audit("model_unloaded" if ok else "model_unload_failed", model=m, status=st)
    return p_installed(f"Unloaded {m}." if ok else f"Ollama refused ({st}): {str(j)[:160]}", ok)


def act_load(form):
    m = form.get("model", "")
    if not MODEL_RE.match(m): return p_installed("Invalid model name.", False)
    st, j = http("POST", OLLAMA + "/api/generate", {"model": m, "keep_alive": "24h"}, timeout=600); ok = st == 200
    audit("model_loaded" if ok else "model_load_failed", model=m, status=st)
    return p_installed(f"Loaded {m}." if ok else f"Ollama refused ({st}): {str(j)[:160]}", ok)


def act_remove(form):
    m = form.get("model", "")
    if form.get("confirm") != m or not MODEL_RE.match(m): return p_installed("Confirmation mismatch.", False)
    st, j = http("DELETE", OLLAMA + "/api/delete", {"name": m}, timeout=60); ok = st == 200
    audit("model_removed" if ok else "model_remove_failed", model=m, status=st)
    return p_installed(f"Removed {m}." if ok else f"Ollama refused ({st}): {str(j)[:200]}", ok)


def act_mint(form):
    alias = form.get("alias", "").strip().lower(); models = form.getlist("models")
    try: rpm, tpm = int(form.get("rpm", 60)), int(form.get("tpm", 200000))
    except ValueError: return p_keys("rpm/tpm must be integers.", False)
    if not ALIAS_RE.match(alias): return p_keys("Alias must be lowercase letters, digits, dot, dash, underscore.", False)
    st, j = litellm("POST", "/key/generate", {"key_alias": alias, "models": models, "rpm_limit": rpm, "tpm_limit": tpm, "metadata": {"minted_by": "hub", "at": now()}})
    ok = st == 200 and isinstance(j, dict) and j.get("key")
    audit("key_minted" if ok else "key_mint_failed", alias=alias, models=",".join(models), rpm=rpm, tpm=tpm, status=st)
    return p_keys(f"Key minted for {alias}." if ok else f"LiteLLM refused ({st}): {str(j)[:200]}", bool(ok), newkey=j.get("key") if ok else None)


def act_keys_update(form):
    alias = form.get("alias", ""); models = [m for m in form.getlist("models") if ALIAS_RE.match(m)]
    st, j = litellm("GET", "/key/list?return_full_object=true&page=1&size=100")
    tok = next((k.get("token") for k in (j.get("keys", []) if isinstance(j, dict) else []) if k.get("key_alias") == alias), None)
    if not tok:
        return p_keys("Key not found.", False)
    st, j = litellm("POST", "/key/update", {"key": tok, "models": models}); ok = st == 200
    audit("key_models_updated" if ok else "key_update_failed", alias=alias, models=",".join(models) or "all", status=st)
    return p_keys(f"Updated models for {alias}: {', '.join(models) or 'all exposed'}." if ok else f"LiteLLM refused ({st}).", ok)


def act_revoke(form):
    alias = form.get("alias", "")
    st, j = litellm("POST", "/key/delete", {"key_aliases": [alias]}); ok = st == 200
    audit("key_revoked" if ok else "key_revoke_failed", alias=alias, status=st)
    return p_keys(f"Revoked {alias}." if ok else f"LiteLLM refused ({st}).", ok)


def act_password(form):
    user = getattr(REQ, "user", "admin"); u = users(); rec = u.get(user)
    cur, new, conf = form.get("current", ""), form.get("new", ""), form.get("confirm", "")
    forced = form.get("forced") == "1"
    render = p_force_password if forced else p_account
    if not rec:
        return render("No such account.", False)
    try:
        PH.verify(rec["hash"], cur)
    except VerifyMismatchError:
        audit("password_change_rejected", reason="current password incorrect"); return render("Current password is incorrect.", False)
    if new != conf: return render("New password and confirmation do not match.", False)
    why = password_policy(new)
    if why: return render(f"Rejected: {why}.", False)
    if hmac.compare_digest(cur, new): return render("New password must differ from the current one.", False)
    rec["hash"] = PH.hash(new); rec["must_change"] = False; rec["updated"] = now(); rec["session_epoch"] = rec.get("session_epoch", 0) + 1
    u[user] = rec; save_users(u); audit("password_changed")
    if forced:
        return None  # caller continues the login flow
    return p_account("Password changed. Other sessions have been signed out.")


def act_mfa_reset(form):
    user = getattr(REQ, "user", "admin"); u = users(); rec = u.get(user)
    try:
        PH.verify(rec["hash"], form.get("current", ""))
    except (VerifyMismatchError, TypeError, KeyError):
        audit("mfa_reset_rejected"); return p_account("Current password is incorrect.", False)
    try:
        sec = fernet().decrypt(rec["totp"].encode()).decode()
    except (InvalidToken, AttributeError):
        return p_account("MFA secret unreadable; use the console reset script.", False)
    c = totp_verify(sec, form.get("code", ""), rec.get("totp_last", 0))
    if c is None:
        audit("mfa_reset_rejected"); return p_account("Authenticator code incorrect.", False)
    rec["totp"] = None; rec["updated"] = now(); rec["session_epoch"] = rec.get("session_epoch", 0) + 1; u[user] = rec; save_users(u)
    audit("mfa_reset")
    return None  # caller redirects to login, which forces enrollment


def act_hostname(form):
    if form.get("action") == "remove":
        try: os.unlink(DOMAIN_FILE)
        except FileNotFoundError: pass
        ok, m = caddy_reload(); audit("hostname_removed", ok=ok, detail=m)
        return p_hostname(f"Removed. {m}", ok)
    host = form.get("hostname", "").strip().lower(); token = form.get("token", "").strip()
    if not HOSTNAME_RE.match(host):
        audit("hostname_rejected", hostname=host); return p_hostname("Rejected: not a valid public DNS name.", False)
    if not token:
        try:
            token = re.search(r"dns cloudflare (\S+)", open(DOMAIN_FILE, encoding="utf-8").read()).group(1)
        except Exception:  # noqa: BLE001
            return p_hostname("A Cloudflare API token is required the first time.", False)
    if not CF_TOKEN_RE.match(token):
        return p_hostname("Rejected: token format not recognised.", False)
    prev = open(DOMAIN_FILE, encoding="utf-8").read() if os.path.exists(DOMAIN_FILE) else None
    tmp = DOMAIN_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(DOMAIN_TEMPLATE.format(ts=now(), hostname=host, token=token))
    os.chmod(tmp, 0o600); os.replace(tmp, DOMAIN_FILE)
    ok, m = caddy_reload()
    if not ok:
        if prev is None: os.unlink(DOMAIN_FILE)
        else: open(DOMAIN_FILE, "w", encoding="utf-8").write(prev)
        caddy_reload()
    audit("hostname_applied" if ok else "hostname_apply_failed", hostname=host, detail=m)
    s = state(); s["hostname"] = host if ok else s.get("hostname", ""); save_json(STATE_FILE, s)
    return p_hostname(f"Applied {host}. Caddy will obtain the certificate via DNS-01 within a minute or two. {m}" if ok else f"Failed and rolled back: {m}", ok)


ACTIONS = {"/hub/api/ops": act_ops, "/hub/api/policy": act_policy, "/hub/api/alerts": act_alerts, "/hub/api/models/pull": act_pull,
           "/hub/api/models/expose": act_expose, "/hub/api/models/unexpose": act_unexpose, "/hub/api/models/remove": act_remove,
           "/hub/api/models/unload": act_unload, "/hub/api/models/load": act_load, "/hub/api/models/setguard": act_setguard,
           "/hub/api/keys/mint": act_mint, "/hub/api/keys/revoke": act_revoke, "/hub/api/keys/update": act_keys_update, "/hub/api/hostname": act_hostname}
PAGES = {("overview", "dashboard"): p_dashboard, ("overview", "services"): p_services, ("safety", "policy"): p_policy,
         ("safety", "audit"): p_audit, ("safety", "alerts"): p_alerts, ("models", "installed"): p_installed,
         ("models", "pull"): p_pull, ("models", "exposed"): p_exposed, ("access", "keys"): p_keys, ("access", "account"): p_account,
         ("gateway", "certs"): p_certs, ("gateway", "hostname"): p_hostname, ("gateway", "isolation"): p_isolation}


class Form(dict):
    def __init__(self, qs):
        self.raw = urllib.parse.parse_qs(qs, keep_blank_values=True)
        super().__init__({k: v[0] for k, v in self.raw.items()})

    def getlist(self, k):
        return self.raw.get(k, [])


class Handler(BaseHTTPRequestHandler):
    server_version = "AegisHub/3"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", cookie=None, location=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store"); self.send_header("X-Frame-Options", "DENY"); self.send_header("Referrer-Policy", "no-referrer")
        if cookie: self.send_header("Set-Cookie", cookie)
        if location: self.send_header("Location", location)
        self.end_headers(); self.wfile.write(data)

    def _redirect(self, to, cookie=None):
        self._send(303, "", "text/plain", cookie=cookie, location=to)

    def _cookie(self, value: str, max_age: int) -> str:
        return f"aegis_hub={value}; Path=/hub; HttpOnly; Secure; SameSite=Strict; Max-Age={max_age}"

    def _session(self) -> str | None:
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "aegis_hub":
                d = unsign(v)
                if d and d.get("kind") == "session":
                    rec = users().get(d.get("u"), {})
                    if rec and d.get("epoch", 0) == rec.get("session_epoch", 0):
                        return d["u"]
        return None

    def _pre(self, user: str, stage: str) -> str:
        return sign({"kind": "pre", "u": user, "stage": stage, "exp": time.time() + 300})

    def _login_ok(self, user: str):
        rec = users()[user]
        tok = sign({"kind": "session", "u": user, "epoch": rec.get("session_epoch", 0), "exp": time.time() + SESSION_TTL, "n": secrets.token_hex(8)})
        audit("login_ok", user=user, ip=client_ip(self)); clear_fail("u:" + user)
        return self._redirect("/hub/overview/dashboard", cookie=self._cookie(tok, SESSION_TTL))

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        REQ.q, REQ.path, REQ.user = urllib.parse.parse_qs(u.query), u.path, None
        p = u.path.rstrip("/") or "/hub"
        if setup_needed():
            return self._send(200, p_setup()) if p == "/hub/setup" else self._redirect("/hub/setup")
        if p == "/hub/setup":
            return self._redirect("/hub/login")
        if p == "/hub/login":
            return self._send(200, p_login())
        if p == "/hub/logout":
            return self._redirect("/hub/login", cookie=self._cookie("", 0))
        user = self._session()
        if not user:
            return self._redirect("/hub/login")
        REQ.user = user
        if users().get(user, {}).get("must_change"):
            return self._send(200, p_force_password())
        if p == "/hub":
            return self._redirect("/hub/overview/dashboard")
        if p == "/hub/api/status":
            dom = current_domain(); cst, cts = container_status()
            return self._send(200, json.dumps({"containers": cst, "status_ts": cts, "lan": probe_cert(LAN_IP), "domain": dom, "public": probe_cert(LAN_IP, dom) if dom else None, "policy": policy()}, indent=1), "application/json")
        parts = p.split("/")
        if len(parts) == 4 and (parts[2], parts[3]) in PAGES:
            return self._send(200, PAGES[(parts[2], parts[3])]())
        self._send(404, "not found", "text/plain")

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        REQ.q, REQ.path, REQ.user = {}, u.path, None
        p = u.path
        n = int(self.headers.get("Content-Length", "0"))
        form = Form(self.rfile.read(min(n, 65536)).decode())
        if form.get("csrf") != CSRF:
            return self._send(403, "invalid or expired form token — reload the page", "text/plain")
        ip = client_ip(self)
        # ---- first-run wizard (only while no account exists) ----
        if p == "/hub/setup":
            if not setup_needed():
                return self._redirect("/hub/login")
            user, pw, conf = form.get("user", "").strip().lower(), form.get("password", ""), form.get("confirm", "")
            if not USER_RE.match(user):
                return self._send(400, p_setup("Username: lowercase letters, digits, dot, dash, underscore.", False))
            if pw != conf:
                return self._send(400, p_setup("Password and confirmation do not match.", False))
            why = password_policy(pw)
            if why:
                return self._send(400, p_setup(f"Rejected: {why}.", False))
            save_users({user: {"hash": PH.hash(pw), "totp": None, "totp_last": 0, "must_change": False, "created": now(), "updated": now(), "session_epoch": 0}})
            REQ.user = user; audit("admin_created_by_wizard", user=user, ip=ip)
            sec = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
            return self._send(200, p_enrol(self._pre(user, "enrol"), sec, user))
        if setup_needed():
            return self._redirect("/hub/setup")
        # ---- login flow (no session) ----
        if p == "/hub/login":
            user, pw = form.get("user", "").strip().lower(), form.get("password", "")
            if locked("ip:" + ip, 20, 900) or locked("u:" + user, 5, 300):
                audit("login_locked", user=user, ip=ip); return self._send(429, p_login("Too many attempts. Try again later.", False))
            rec = users().get(user) if USER_RE.match(user) else None
            try:
                if not rec: raise VerifyMismatchError
                PH.verify(rec["hash"], pw)
            except VerifyMismatchError:
                fail("ip:" + ip); fail("u:" + user); audit("login_failed", user=user, ip=ip); time.sleep(0.5)
                return self._send(401, p_login("Invalid username or password.", False))
            if not rec.get("totp"):
                sec = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
                return self._send(200, p_enrol(self._pre(user, "enrol"), sec, user))
            return self._send(200, p_totp(self._pre(user, "totp")))
        if p in ("/hub/login/totp", "/hub/login/enrol"):
            d = unsign(form.get("pre", ""))
            if not d or d.get("kind") != "pre":
                return self._send(401, p_login("Session expired; sign in again.", False))
            user = d["u"]; u_all = users(); rec = u_all.get(user)
            if not rec:
                return self._send(401, p_login("Invalid session.", False))
            if locked("ip:" + ip, 20, 900) or locked("u:" + user, 5, 300):
                audit("login_locked", user=user, ip=ip); return self._send(429, p_login("Too many attempts. Try again later.", False))
            if p == "/hub/login/enrol" and d.get("stage") == "enrol":
                sec = form.get("secret", "")
                if not re.fullmatch(r"[A-Z2-7]{32}", sec):
                    return self._send(400, p_login("Invalid enrollment.", False))
                c = totp_verify(sec, form.get("code", ""), 0)
                if c is None:
                    fail("u:" + user); audit("mfa_enroll_failed", user=user, ip=ip)
                    return self._send(401, p_enrol(self._pre(user, "enrol"), sec, user, "Code did not match — check the clock on your device and try again.", False))
                rec["totp"] = fernet().encrypt(sec.encode()).decode(); rec["totp_last"] = c; rec["updated"] = now(); u_all[user] = rec; save_users(u_all)
                REQ.user = user; audit("mfa_enrolled", user=user, ip=ip)
                return self._login_ok(user)
            if p == "/hub/login/totp" and d.get("stage") == "totp":
                try: sec = fernet().decrypt(rec["totp"].encode()).decode()
                except (InvalidToken, AttributeError): return self._send(500, p_login("MFA secret unreadable; use the console reset script.", False))
                c = totp_verify(sec, form.get("code", ""), rec.get("totp_last", 0))
                if c is None:
                    fail("ip:" + ip); fail("u:" + user); audit("mfa_failed", user=user, ip=ip); time.sleep(0.5)
                    return self._send(401, p_totp(self._pre(user, "totp"), "Code incorrect or already used.", False))
                rec["totp_last"] = c; u_all[user] = rec; save_users(u_all); REQ.user = user
                return self._login_ok(user)
            return self._send(400, p_login("Invalid step.", False))
        # ---- everything else needs a session ----
        user = self._session()
        if not user:
            return self._redirect("/hub/login")
        REQ.user = user
        if users().get(user, {}).get("must_change") and p != "/hub/account/password":
            return self._send(200, p_force_password())
        if p == "/hub/account/password":
            out = act_password(form)
            if out is None:
                return self._login_ok(user)   # forced change completed -> new epoch session
            rec = users().get(user, {}); tok = sign({"kind": "session", "u": user, "epoch": rec.get("session_epoch", 0), "exp": time.time() + SESSION_TTL, "n": secrets.token_hex(8)})
            return self._send(200, out, cookie=self._cookie(tok, SESSION_TTL))
        if p == "/hub/account/mfa-reset":
            out = act_mfa_reset(form)
            if out is None:
                return self._redirect("/hub/login", cookie=self._cookie("", 0))
            return self._send(200, out)
        fn = ACTIONS.get(p)
        if not fn:
            return self._send(404, "not found", "text/plain")
        try:
            self._send(200, fn(form))
        except (BrokenPipeError, ConnectionResetError):
            return  # client navigated away mid-action; the action itself completed and was audited
        except Exception as e:  # noqa: BLE001
            audit("hub_error", path=p, error=str(e)[:200])
            try:
                self._send(500, p_dashboard(f"Action failed: {e}", False))
            except (BrokenPipeError, ConnectionResetError):
                return


if __name__ == "__main__":
    if not SECRET or len(SECRET) < 32:
        raise SystemExit("HUB_SECRET_KEY (>= 32 chars) is required")
    for d in (SITES_DIR, STATE_DIR, os.path.dirname(OPS_REQ)):
        os.makedirs(d, exist_ok=True)
    if "--reset-admin" in sys.argv:
        reset_admin(); raise SystemExit(0)
    if "--totp-now" in sys.argv:   # console helper for the acceptance suite
        rec = users().get("admin", {})
        print(totp_now(fernet().decrypt(rec["totp"].encode()).decode()) if rec.get("totp") else "not-enrolled"); raise SystemExit(0)
    if not os.path.exists(POLICY_FILE):
        save_json(POLICY_FILE, DEFAULT_POLICY)
    threading.Thread(target=_veto_watcher, name="veto-watcher", daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", 9000), Handler).serve_forever()
