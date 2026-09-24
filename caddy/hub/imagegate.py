"""Aegis hub — image generation gate (ComfyUI), gallery, per-file model attributes, sealed evidence for images.

Mounted read-only into the hub next to hub.py. Design: docs/designs/portal-and-identity.md ("NSFW model files in
ComfyUI", "Gallery and the image safety gate"). Rules enforced here, never in the UI:

* Prompt gate — the hub sends every text input of a workflow through LiteLLM (VetoGuard) before ComfyUI sees it
  (done in hub.py with the user's own key; this module extracts the texts).
* File gate — every string input that names a file in the model store is checked against the attribute
  registry: NSFW or unclassified files need the `images_nsfw` grant (unclassified: administrators only).
* Output gate — every produced image is classified by a vision model before anyone can see it. Illegal / minor
  sexual content: destroyed, immutable audit, sealed evidence (prompt, files, verdict, perceptual hash — never
  the image). NSFW without the grant: destroyed, audited. Unreadable verdict: destroyed (fail closed).
* Gallery — approved images live under gallery/<user>/; users purge their own; admins may review when policy says.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import math
import os
import re
import threading
import time
import urllib.request
from datetime import datetime, timezone

STORE = os.environ.get("COMFY_STORE", "/app/comfy-store")
GALLERY = os.environ.get("GALLERY_DIR", "/app/gallery")
EVIDENCE_DIR = "/app/evidence"
ATTR_FILE = os.path.join(STORE, ".aegis-attributes.json")
MODEL_DIRS = ("checkpoints", "loras", "vae", "controlnet", "upscale_models", "embeddings", "motion", "unet", "clip", "clip_vision", "diffusion_models", "text_encoders")
MODEL_EXT = (".safetensors", ".gguf", ".ckpt", ".pt", ".pth", ".bin", ".sft")
_LOCK = threading.Lock()

LLAMA_GUARD_NAMES = {"S1": "Violent Crimes", "S2": "Non-Violent Crimes", "S3": "Sex Crimes", "S4": "Child Exploitation", "S9": "Indiscriminate Weapons",
                     "S10": "Hate", "S11": "Self-Harm", "S12": "Sexual Content"}


# ---------------------------------------------------------------- model store attributes ------
def inventory() -> dict[str, str]:
    """basename -> relative path for every model file in the store."""
    out = {}
    for d in MODEL_DIRS:
        base = os.path.join(STORE, d)
        if not os.path.isdir(base):
            continue
        for root, _, files in os.walk(base):
            for f in files:
                if f.lower().endswith(MODEL_EXT) and not f.endswith(".part"):
                    out[f] = os.path.relpath(os.path.join(root, f), STORE)
    return out


def attrs() -> dict:
    try:
        with open(ATTR_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {}


def set_attr(name: str, nsfw: str, by: str, source: str | None = None, sha256: str | None = None) -> None:
    assert nsfw in ("yes", "no", "unclassified")
    with _LOCK:
        a = attrs(); rec = a.get(name, {})
        rec.update({"nsfw": nsfw, "set_by": by, "ts": datetime.now(timezone.utc).isoformat()})
        if source: rec["source"] = source
        if sha256: rec["sha256"] = sha256
        a[name] = rec
        tmp = ATTR_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(a, f, indent=1, sort_keys=True)
        os.chmod(tmp, 0o600); os.replace(tmp, ATTR_FILE)


def attr_of(name: str) -> str:
    return (attrs().get(name) or {}).get("nsfw", "unclassified")


def store_listing() -> list[dict]:
    a = attrs(); inv = inventory()
    return sorted([{"name": n, "path": p, "size": os.path.getsize(os.path.join(STORE, p)), "nsfw": (a.get(n) or {}).get("nsfw", "unclassified"),
                    "source": (a.get(n) or {}).get("source", ""), "set_by": (a.get(n) or {}).get("set_by", "")} for n, p in inv.items()], key=lambda x: (x["path"]))


# ---------------------------------------------------------------- workflow inspection --------
def _walk_strings(workflow: dict):
    for nid, node in (workflow or {}).items():
        if not isinstance(node, dict):
            continue
        for k, v in (node.get("inputs") or {}).items():
            if isinstance(v, str):
                yield nid, node.get("class_type", ""), k, v


def file_refs(workflow: dict) -> list[str]:
    inv = inventory(); seen = []
    for _, _, _, v in _walk_strings(workflow):
        b = os.path.basename(v.replace("\\", "/"))
        if b in inv and b not in seen:
            seen.append(b)
    return seen


def text_inputs(workflow: dict) -> list[str]:
    """Every string input that is not a model file — prompts, but also anything a custom node might carry."""
    inv = inventory(); out = []
    for _, cls, k, v in _walk_strings(workflow):
        if os.path.basename(v.replace("\\", "/")) in inv or not v.strip():
            continue
        out.append(v)
    return out


def files_allowed(names: list[str], user_nsfw: bool, is_admin: bool) -> tuple[bool, str]:
    a = attrs()
    for n in names:
        flag = (a.get(n) or {}).get("nsfw", "unclassified")
        if flag == "yes" and not user_nsfw:
            return False, f"{n} is marked NSFW and your account does not have the NSFW grant"
        if flag == "unclassified" and not (is_admin and user_nsfw or is_admin):
            return False, f"{n} has not been classified by an administrator yet"
    return True, ""


# ---------------------------------------------------------------- output classifier ----------
VERDICT_PROMPT = ("You are a strict image safety classifier for a content platform. Look at the image and answer with JSON only, no prose: "
                  '{"nsfw": true|false, "sexual_content": true|false, "minor_present": true|false, "sexual_minor": true|false, '
                  '"illegal": true|false, "violence_gore": true|false, "description": "<at most 12 words>"}. '
                  "nsfw = nudity or sexual content or extreme gore. minor_present = any person who appears under 18. "
                  "sexual_minor = any sexualised depiction of a person who could be under 18 (be conservative: if in doubt, true). "
                  "illegal = sexual content involving minors, non-consensual sexual content, or instructions/imagery for terrorism or weapons of mass destruction.")
REQUIRED = ("nsfw", "sexual_content", "minor_present", "sexual_minor", "illegal", "violence_gore")


def classify_image(path: str, model: str, ollama_url: str, timeout: int = 180) -> dict:
    """Vision-model verdict. Returns {"ok": bool, "verdict": dict|None, "raw": str, "error": str|None, "seconds": float}."""
    t = time.time()
    try:
        with open(path, "rb") as f:
            img = base64.b64encode(f.read()).decode()
        req = urllib.request.Request(ollama_url + "/api/chat", data=json.dumps({"model": model, "messages": [{"role": "user", "content": VERDICT_PROMPT, "images": [img]}],
                                     "stream": False, "format": "json", "options": {"temperature": 0, "num_predict": 160}}).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = (json.loads(r.read()).get("message") or {}).get("content") or ""
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "verdict": None, "raw": "", "error": f"classifier unavailable: {str(e)[:160]}", "seconds": round(time.time() - t, 1)}
    try:
        v = json.loads(raw)
        if not isinstance(v, dict) or any(not isinstance(v.get(k), bool) for k in REQUIRED):
            raise ValueError("missing or non-boolean fields")
    except ValueError as e:
        return {"ok": False, "verdict": None, "raw": raw[:300], "error": f"unparseable verdict ({e}); expected JSON with boolean {', '.join(REQUIRED)}", "seconds": round(time.time() - t, 1)}
    v["description"] = str(v.get("description", ""))[:120]
    return {"ok": True, "verdict": v, "raw": raw[:300], "error": None, "seconds": round(time.time() - t, 1)}


def decide(res: dict, user_nsfw: bool) -> tuple[str, str, list[str]]:
    """-> (action, reason, category codes). action: keep | destroy_nsfw | destroy_illegal | destroy_unparseable"""
    if not res["ok"]:
        return "destroy_unparseable", res["error"] or "unparseable", ["UNPARSEABLE_VERDICT"]
    v = res["verdict"]
    if v["sexual_minor"] or (v["minor_present"] and (v["nsfw"] or v["sexual_content"])):
        return "destroy_illegal", "sexualised minor", ["S4"]
    if v["illegal"]:
        return "destroy_illegal", "illegal content", ["S3"]
    if (v["nsfw"] or v["sexual_content"] or v["violence_gore"]) and not user_nsfw:
        return "destroy_nsfw", "NSFW output without the NSFW grant", ["S12"]
    return "keep", "", []


# ---------------------------------------------------------------- perceptual hash -------------
def phash(path: str) -> str | None:
    """64-bit DCT perceptual hash (pHash). Robust to resizing/re-encoding; lets law enforcement match a destroyed
    image against holdings without the platform ever storing it."""
    try:
        from PIL import Image
        im = Image.open(path).convert("L").resize((32, 32), Image.LANCZOS)
        px = list(im.getdata()); N = 32
        cos = [[math.cos((2 * x + 1) * u * math.pi / (2 * N)) for x in range(N)] for u in range(N)]
        rows = [[sum(px[y * N + x] * cos[u][x] for x in range(N)) for u in range(8)] for y in range(N)]
        dct = [[sum(rows[y][u] * cos[v][y] for y in range(N)) for u in range(8)] for v in range(8)]
        vals = [dct[v][u] for v in range(8) for u in range(8)][1:]
        med = sorted(vals)[len(vals) // 2]
        bits = "".join("1" if val > med else "0" for val in [dct[v][u] for v in range(8) for u in range(8)])
        return f"{int(bits, 2):016x}"
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------- sealed evidence -------------
def seal_evidence(evidence_key: str, user: str, prompt_texts: list[str], files: list[str], verdict: dict | None, codes: list[str], reason: str,
                  ph: str | None, ip: str, device_fp: str, prompt_id: str, model: str) -> str | None:
    """Same record shape and hash chain as VetoGuard's text evidence (proxy/veto_filter.py write_evidence), written
    under a file lock so both writers share one chain. The image itself is never stored."""
    if not evidence_key:
        return None
    from cryptography.fernet import Fernet
    f = Fernet(base64.urlsafe_b64encode(hashlib.sha256(evidence_key.encode()).digest()))
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    rid = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + hashlib.sha256(os.urandom(16)).hexdigest()[:8]
    cats = [{"code": c, "name": LLAMA_GUARD_NAMES.get(c, "")} for c in codes]
    rec = {"id": rid, "ts": datetime.now(timezone.utc).isoformat(), "stage": "image_output", "reason": "classifier", "detail": " ".join(f"{c['code']} {c['name']}".strip() for c in cats) + f" — {reason}",
           "categories": cats, "matches": [], "call_id": prompt_id, "model": model, "key_alias": f"portal-{user}", "client_ip": ip, "device_fingerprint": device_fp or "none",
           "request": {"prompt_texts": prompt_texts, "workflow_files": files}, "output": None,
           "image": {"stored": False, "destroyed": True, "phash_dct64": ph, "classifier_verdict": verdict}}
    chain = os.path.join(EVIDENCE_DIR, "chain.txt"); lockp = os.path.join(EVIDENCE_DIR, ".chain.lock")
    with open(lockp, "a+") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        prev = open(chain).read().strip() if os.path.exists(chain) else "GENESIS"
        body = json.dumps(rec, sort_keys=True, ensure_ascii=False)
        h = hashlib.sha256((prev + body).encode()).hexdigest()
        rec["prev_hash"], rec["hash"] = prev, h
        path = os.path.join(EVIDENCE_DIR, rid + ".json.enc")
        with open(path, "wb") as fh:
            fh.write(f.encrypt(json.dumps(rec, sort_keys=True, ensure_ascii=False).encode()))
        os.chmod(path, 0o600)
        with open(chain, "w") as fh:
            fh.write(h)
        with open(os.path.join(EVIDENCE_DIR, "index.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"id": rid, "ts": rec["ts"], "stage": "image_output", "reason": "classifier", "categories": codes, "key_alias": rec["key_alias"], "hash": h}) + "\n")
        fcntl.flock(lk, fcntl.LOCK_UN)
    return rid


def destroy(path: str) -> None:
    """Overwrite then unlink — the file never survives, even in a copied-forward filesystem snapshot window."""
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(b"\x00" * min(size, 1 << 20)); f.flush(); os.fsync(f.fileno())
    except OSError:
        pass
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------- gallery ---------------------
SAFE_USER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,40}$")


def _udir(user: str) -> str:
    if not SAFE_USER.match(user):
        raise ValueError("bad user")
    d = os.path.join(GALLERY, user); os.makedirs(d, mode=0o750, exist_ok=True)
    return d


def gallery_add(user: str, src: str, meta: dict) -> str:
    d = _udir(user); gid = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")[:-3] + "-" + hashlib.sha256(os.urandom(8)).hexdigest()[:6]
    ext = os.path.splitext(src)[1].lower() or ".png"
    dst = os.path.join(d, gid + ext)
    import shutil
    shutil.copyfile(src, dst); os.chmod(dst, 0o640)      # output/ and gallery/ are different mounts: copy, then wipe the source
    destroy(src)
    meta = {**meta, "id": gid, "file": os.path.basename(dst), "ts": datetime.now(timezone.utc).isoformat(), "user": user}
    with open(os.path.join(d, gid + ".json"), "w", encoding="utf-8") as f:
        json.dump(meta, f)
    return gid


def gallery_list(user: str) -> list[dict]:
    d = _udir(user); out = []
    for f in os.listdir(d):
        if f.endswith(".json"):
            try:
                with open(os.path.join(d, f), encoding="utf-8") as fh:
                    m = json.load(fh)
                p = os.path.join(d, m.get("file", ""))
                m["size"] = os.path.getsize(p) if os.path.exists(p) else 0
                out.append(m)
            except (ValueError, OSError):
                continue
    return sorted(out, key=lambda m: m.get("ts", ""), reverse=True)


def gallery_path(user: str, gid: str) -> str | None:
    if not re.fullmatch(r"[0-9TZ]+-[0-9a-f]{6}", gid):
        return None
    d = _udir(user)
    for f in os.listdir(d):
        if f.startswith(gid + ".") and not f.endswith(".json"):
            return os.path.join(d, f)
    return None


def gallery_delete(user: str, gids: list[str]) -> list[str]:
    """Full deletion: image overwritten and unlinked, metadata removed. Returns the prompt ids so the caller can
    drop ComfyUI's history entries too."""
    d = _udir(user); prompt_ids = []
    for gid in gids:
        p = gallery_path(user, gid)
        mp = os.path.join(d, gid + ".json")
        if os.path.exists(mp):
            try:
                with open(mp, encoding="utf-8") as fh:
                    prompt_ids.append(json.load(fh).get("prompt_id"))
            except ValueError:
                pass
            os.unlink(mp)
        if p:
            destroy(p)
    return [x for x in prompt_ids if x]


def gallery_users() -> list[str]:
    os.makedirs(GALLERY, exist_ok=True)
    return sorted(u for u in os.listdir(GALLERY) if os.path.isdir(os.path.join(GALLERY, u)))
