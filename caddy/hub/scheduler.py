"""Aegis hub — request-driven model scheduling for the chat pool, with administrator precedence.

Design: docs/designs/gpu-runtime-and-scheduling.md (phase 2). Mounted read-only next to hub.py; the hub passes in
its HTTP helper, pool map, policy and audit so this module has no state of its own beyond the in-memory use table.

Rules (enforced here, never in the UI):
* Users never load or unload anything themselves. A user picks an exposed model; the scheduler makes it resident
  on its pool if policy allows, evicting what it must.
* The safety pool is never touched: classifiers are loaded by policy only (hub activate_guard / image classifier).
* Administrator precedence: a request from an administrator may evict any chat model; a request from a user may
  not evict a model that is pinned by an administrator, that an administrator used within `admin_hold_min`, or that
  has a request in flight. Users are told why and what else is available.
* "Wide" chat mode (both Intel cards for one large chat model) suspends image generation. Only administrators can
  switch to it; it reverts to normal automatically after `wide_idle_min` minutes without chat traffic, and users'
  image requests are refused with a clear message while it is on.
"""
from __future__ import annotations

import json
import os
import threading
import time

_LOCK = threading.Lock()
USE: dict[str, dict] = {}          # model -> {"ts": last use, "admin": bool, "inflight": int}
DEFAULTS = {"admin_hold_min": 10, "wide_idle_min": 20, "pinned": [], "wait_s": 45}


def cfg(policy: dict) -> dict:
    c = dict(DEFAULTS); c.update(policy.get("scheduler") or {}); return c


def _base(n: str) -> str:
    return n.removesuffix(":latest")


def note_use(model: str, admin: bool, start: bool) -> None:
    with _LOCK:
        u = USE.setdefault(model, {"ts": 0, "admin": False, "inflight": 0})
        u["ts"] = time.time()
        if admin:
            u["admin"] = True; u["admin_ts"] = time.time()
        u["inflight"] = max(0, u["inflight"] + (1 if start else -1))


def protected(model: str, policy: dict) -> str | None:
    """Why a USER may not evict this model right now (None = may evict)."""
    c = cfg(policy)
    if _base(model) in {_base(x) for x in c["pinned"]}:
        return "pinned by an administrator"
    u = USE.get(model) or {}
    if u.get("inflight", 0) > 0:
        return "answering another request"
    if u.get("admin_ts") and time.time() - u["admin_ts"] < c["admin_hold_min"] * 60:
        return f"in use by an administrator (held {c['admin_hold_min']} min)"
    return None


def resident(http, url: str) -> list[dict]:
    """Models actually held on the pool. Ollama keeps an evicted model in /api/ps until it has finished unloading,
    with `expires_at` already in the past — those are not resident for scheduling purposes."""
    from datetime import datetime, timezone
    st, ps = http("GET", url + "/api/ps", timeout=5)
    out = []
    for m in (ps.get("models", []) if isinstance(ps, dict) else []):
        exp = m.get("expires_at") or ""
        try:
            if exp and datetime.fromisoformat(exp.replace("Z", "+00:00")) <= datetime.now(timezone.utc):
                continue
        except ValueError:
            pass
        out.append(m)
    return out


def ensure_resident(http, url: str, model: str, admin: bool, policy: dict, audit, exclude: set[str] = frozenset()) -> tuple[bool, str]:
    """Make `model` resident on the pool at `url`. Returns (ok, message). Evicts by policy; waits briefly for
    in-flight answers instead of cutting them off."""
    c = cfg(policy); deadline = time.time() + c["wait_s"]
    while True:
        res = resident(http, url)
        if any(_base(m.get("name", "")) == _base(model) for m in res):
            return True, ""
        others = [m for m in res if _base(m.get("name", "")) != _base(model) and m.get("name") not in exclude]
        blocked = [(m["name"], protected(m["name"], policy)) for m in others]
        blocked = [(n, why) for n, why in blocked if why]
        if others and blocked and not admin:
            if any(why == "answering another request" for _, why in blocked) and time.time() < deadline:
                time.sleep(2); continue
            n, why = blocked[0]
            return False, f"{model} cannot be loaded right now: {n} is {why}. Pick a model that is already loaded, or try again later."
        for m in others:                                   # evict (admin: always; user: only unprotected)
            http("POST", url + "/api/generate", {"model": m["name"], "keep_alive": 0}, timeout=120)
            audit("model_evicted", model=m["name"], for_model=model, by="admin" if admin else "user")
        for _ in range(15):                                # let the eviction finish before loading (no VRAM overlap)
            if not any(_base(m.get("name", "")) != _base(model) for m in resident(http, url)):
                break
            time.sleep(1)
        st, j = http("POST", url + "/api/generate", {"model": model, "keep_alive": "24h"}, timeout=900)
        if st == 200:
            audit("model_loaded", model=model, pool=url, by="scheduler", requester="admin" if admin else "user")
            return True, ""
        return False, f"the engine could not load {model} ({st}): {str(j)[:120]}"


# ---------------------------------------------------------------- chat pool mode -------------
def mode(http, narrow_url: str, wide_url: str) -> str:
    """'wide' when the wide container answers, 'narrow' when the normal one does, 'switching' otherwise."""
    st, _ = http("GET", wide_url + "/api/version", timeout=3)
    if st == 200:
        return "wide"
    st, _ = http("GET", narrow_url + "/api/version", timeout=3)
    return "narrow" if st == 200 else "switching"


def mode_steps(target: str) -> list[dict]:
    """Ordered watchdog steps for a mode switch. Wide: images down, normal pool down, wide pool up.
    Narrow: wide pool down, normal pool up, images up."""
    if target == "wide":
        return [{"action": "stop", "targets": ["comfyui-intel"]}, {"action": "stop", "targets": ["ollama-intel"]}, {"action": "start", "targets": ["ollama-intel-wide"]}]
    return [{"action": "stop", "targets": ["ollama-intel-wide"]}, {"action": "start", "targets": ["ollama-intel"]}, {"action": "start", "targets": ["comfyui-intel"]}]


def last_chat_use() -> float:
    with _LOCK:
        return max((u.get("ts", 0) for u in USE.values()), default=0)
