#!/usr/bin/env python3
"""
aegis-watchdog — host-side service controller for the Aegis stack. Runs as root under systemd,
OUTSIDE Docker. No container holds the Docker socket.

Contract (the only input is a file):
  <OPS>/requests/request.json   written by the hub (one file = one operation; never more than one pending)
      {"id": "...", "ts": "...", "action": "start|stop|restart", "targets": ["caddy", ...] | ["*"], "requested_by": "..."}
  <OPS>/responses/<ts>-<id>.json   result: per-step log, ok flag, errors. Request moves to <OPS>/archive/.
  <OPS>/responses/status.json      rewritten every STATUS_EVERY seconds: state/health of every allow-listed container.

Rules:
  * targets must be allow-listed names; unknown names reject the whole request (nothing runs).
  * PROTECTED containers (caddy, hub) can be restarted but never stopped — the hub lives in caddy's netns
    and is the only way to bring things back without the console.
  * dependents are stopped deepest-first before their dependency is touched and started shallowest-first after.
  * no shell: fixed argv to the docker CLI, names only from the allow-list.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timezone

OPS = os.environ.get("AEGIS_OPS_DIR", "/data/ai-unified/ops")
REQ = os.path.join(OPS, "requests", "request.json")
RESP_DIR = os.path.join(OPS, "responses")
ARCHIVE = os.path.join(OPS, "archive")
STATUS = os.path.join(RESP_DIR, "status.json")
POLL, STATUS_EVERY = 2, 5

DEPENDENTS = {                      # name -> direct dependents (must be down while name restarts)
    "caddy": ["hub"], "hub": [], "litellm-db": ["litellm"], "ollama": ["litellm"], "ollama-intel": ["litellm"], "litellm": [],
    "openwebui": [], "modeld": [], "prometheus": ["grafana"], "grafana": [], "node-exporter": [], "dcgm-exporter": [],
    "fish-speech": [], "comfyui": [],
}
ALLOWED = set(DEPENDENTS)
PROTECTED = {"caddy", "hub"}
ACTIONS = {"start", "stop", "restart"}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def docker(*args: str, timeout=180) -> tuple[int, str]:
    try:
        p = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s"


def state(name: str) -> dict:
    rc, out = docker("inspect", "-f", "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.State.StartedAt}}|{{.State.ExitCode}}", name, timeout=20)
    if rc != 0:
        return {"status": "absent", "health": "", "started": "", "exit": None}
    st, h, started, ex = (out.split("|") + ["", "", "", ""])[:4]
    return {"status": st, "health": h, "started": started, "exit": int(ex) if ex.lstrip("-").isdigit() else None}


def wait_up(name: str, secs: int = 120) -> bool:
    for _ in range(secs):
        s = state(name)
        if s["status"] == "running" and s["health"] in ("", "healthy"):
            return True
        time.sleep(1)
    return state(name)["status"] == "running"


def closure(names: list[str]) -> list[str]:
    """Dependents of the given names, in shutdown order (deepest first), excluding the names themselves."""
    order: list[str] = []
    def walk(n):
        for d in DEPENDENTS.get(n, []):
            walk(d)
            if d not in order and d not in names:
                order.append(d)
    for n in names:
        walk(n)
    return order


def topo(names: list[str]) -> list[str]:
    """Start order: dependencies before dependents."""
    deps_of = {n: [k for k, v in DEPENDENTS.items() if n in v] for n in ALLOWED}
    out, seen = [], set()
    def visit(n):
        if n in seen: return
        seen.add(n)
        for d in deps_of.get(n, []):
            if d in names: visit(d)
        out.append(n)
    for n in names: visit(n)
    return out


def run(req: dict) -> dict:
    log, errors = [], []
    action = req.get("action"); raw = req.get("targets")
    if action not in ACTIONS:
        return {"ok": False, "errors": [f"unknown action {action!r}"], "log": []}
    if not isinstance(raw, list) or not raw:
        return {"ok": False, "errors": ["targets must be a non-empty list"], "log": []}
    targets = sorted(ALLOWED) if raw == ["*"] else [str(t) for t in raw]
    bad = [t for t in targets if t not in ALLOWED]
    if bad:
        return {"ok": False, "errors": [f"not allow-listed: {bad}"], "log": []}
    if action == "stop" and (set(targets) & PROTECTED):
        return {"ok": False, "errors": [f"{sorted(set(targets) & PROTECTED)} may only be restarted, never stopped"], "log": []}
    # skip containers that don't exist (profiles not started)
    present = [t for t in targets if state(t)["status"] != "absent"]
    for t in targets:
        if t not in present:
            log.append(f"{t}: not present (profile not started) — skipped")
    deps = closure(present)
    if action in ("stop", "restart"):
        for d in deps:
            if state(d)["status"] == "running":
                rc, out = docker("stop", "-t", "20", d); log.append(f"stop dependent {d}: {'ok' if rc == 0 else out}")
                if rc: errors.append(f"stop {d}: {out}")
        for t in reversed(topo(present)) if action == "stop" else present:
            rc, out = docker(action, "-t", "20", t) if action != "start" else docker("start", t)
            log.append(f"{action} {t}: {'ok' if rc == 0 else out}")
            if rc: errors.append(f"{action} {t}: {out}")
            if action == "restart":
                up = wait_up(t); log.append(f"wait {t}: {'running' if up else state(t)['status']}")
                if not up: errors.append(f"{t} did not come up")
        if action == "restart":
            for d in reversed(deps):
                rc, out = docker("start", d); log.append(f"start dependent {d}: {'ok' if rc == 0 else out}")
                up = wait_up(d); log.append(f"wait {d}: {'running' if up else state(d)['status']}")
                if rc or not up: errors.append(f"start {d}: {out or 'did not come up'}")
    else:  # start
        for t in topo(present):
            rc, out = docker("start", t); log.append(f"start {t}: {'ok' if rc == 0 else out}")
            up = wait_up(t); log.append(f"wait {t}: {'running' if up else state(t)['status']}")
            if rc or not up: errors.append(f"start {t}: {out or 'did not come up'}")
    return {"ok": not errors, "errors": errors, "log": log}


def write_status() -> None:
    st = {n: state(n) for n in sorted(ALLOWED)}
    tmp = STATUS + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"ts": now(), "containers": st}, f)
    os.chmod(tmp, 0o644); os.replace(tmp, STATUS)


def main() -> None:
    for d in (os.path.dirname(REQ), RESP_DIR, ARCHIVE):
        os.makedirs(d, exist_ok=True)
    last_status = 0.0
    while True:
        if os.path.exists(REQ):
            rid = "unknown"
            try:
                with open(REQ, encoding="utf-8") as f:
                    req = json.load(f)
                rid = str(req.get("id", "unknown"))[:32]
                res = run(req)
            except Exception as e:  # noqa: BLE001
                res = {"ok": False, "errors": [f"invalid request: {type(e).__name__}: {e}"], "log": []}
                req = {}
            res.update({"id": rid, "request": {k: req.get(k) for k in ("action", "targets", "requested_by", "ts")}, "completed": now()})
            name = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{rid}.json"
            with open(os.path.join(RESP_DIR, name), "w", encoding="utf-8") as f:
                json.dump(res, f, indent=1)
            os.chmod(os.path.join(RESP_DIR, name), 0o644)
            try:
                os.replace(REQ, os.path.join(ARCHIVE, name))
            except OSError:
                os.unlink(REQ)
            write_status(); last_status = time.time()
        elif time.time() - last_status > STATUS_EVERY:
            try:
                write_status()
            except OSError:
                pass
            last_status = time.time()
        time.sleep(POLL)


if __name__ == "__main__":
    main()
