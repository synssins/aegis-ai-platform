"""Aegis hub — image generation gate (ComfyUI), gallery, per-file model attributes.

Mounted read-only into the hub next to hub.py. Design: docs/designs/portal-and-identity.md ("NSFW model files in
ComfyUI", "Gallery and the image safety gate"). Rules enforced here, never in the UI:

* Prompt gate — the hub sends every text input of a workflow through LiteLLM (VetoGuard) before ComfyUI sees it
  (done in hub.py with the user's own key; this module extracts the texts).
* File gate — every string input that names a file in the model store is checked against the attribute
  registry: NSFW or unclassified files need the `images_nsfw` grant (unclassified: administrators only).
* Output gate — every produced image is classified by a vision model before anyone can see it. Illegal / minor
  sexual content: destroyed, immutable metadata-only audit entry, nothing else kept (zero retention — no evidence
  store, no hashes, no prompt copies). NSFW without the grant: destroyed, audited. Unreadable verdict: destroyed
  (fail closed).
* Gallery — approved images live under gallery/<user>/; users purge their own; admins may review when policy says.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import threading
import time
import urllib.request
from datetime import datetime, timezone

STORE = os.environ.get("COMFY_STORE", "/app/comfy-store")
GALLERY = os.environ.get("GALLERY_DIR", "/app/gallery")
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


def is_model_file_value(v: str, inv: dict[str, str] | None = None) -> bool:
    """True only when the WHOLE value names a model file exactly as ComfyUI writes it ("x.safetensors" or
    "subdir/x.safetensors" relative to its model folder). Audit H4: the old suffix test skipped any text that merely
    ENDED in a model filename, so "<any prompt> /Model.safetensors" was never checked."""
    inv = inventory() if inv is None else inv
    norm = v.replace("\\", "/").strip()
    b = os.path.basename(norm)
    if b not in inv:
        return False
    rel_in_folder = inv[b].split("/", 1)[1] if "/" in inv[b] else inv[b]
    return norm in (b, rel_in_folder)


# Node allow-list (audit H4). A workflow is a program; only node classes known to be safe may run. The default set covers
# core text-to-image, img2img, upscale, LoRA and ControlNet graphs (and every tracked Aegis workflow). Administrators can
# add classes in Safety -> VetoGuard policy -> Image gate; text-rewriting classes are refused even if added there.
DEFAULT_ALLOWED_NODES = frozenset({
    "CheckpointLoaderSimple", "VAELoader", "LoraLoader", "LoraLoaderModelOnly", "CLIPSetLastLayer", "UpscaleModelLoader",
    "ControlNetLoader", "ControlNetApply", "ControlNetApplyAdvanced",
    "CLIPTextEncode", "CLIPTextEncodeSDXL", "CLIPTextEncodeSDXLRefiner",
    "ConditioningCombine", "ConditioningConcat", "ConditioningSetArea", "ConditioningZeroOut",
    "KSampler", "KSamplerAdvanced", "EmptyLatentImage", "LatentUpscale", "LatentUpscaleBy", "RepeatLatentBatch", "LatentFromBatch",
    "SetLatentNoiseMask", "VAEDecode", "VAEEncode", "VAEEncodeForInpaint",
    "LoadImage", "LoadImageMask", "SaveImage", "PreviewImage",
    "ImageScale", "ImageScaleBy", "ImageScaleToTotalPixels", "ImageUpscaleWithModel", "ImageCrop", "ImageInvert", "ImagePadForOutpaint",
    "PrimitiveInt", "PrimitiveFloat", "PrimitiveBoolean", "PrimitiveString", "PrimitiveStringMultiline",
})
# Classes that rewrite, join, load or generate text AFTER the prompt gate has read it — never allowed.
TEXT_TRANSFORM_NODE_RE = re.compile(r"(?i)(^string|string(concat|replace|substring|trim|compare|contains|length|join|split|format|function)|strings?$|regex|caseconvert|"
                                    r"text[ _]?(concat|replace|join|combine|transform|format|template|load|file)|concat|combine ?prompt|prompt ?(concat|styler|combine|from|load)|"
                                    r"styler|wildcard|dynamicprompt|base64|translat|load ?(text|prompt)|from ?file|ollama|llm|caption|florence|gpt|gemini)")


# Exact core classes whose names look textual but only carry a value (checked by the gate) or join conditioning.
TRANSFORM_EXEMPT = frozenset({"ConditioningConcat", "PrimitiveString", "PrimitiveStringMultiline"})


def text_transform_nodes(workflow: dict) -> list[str]:
    """class_types that could rewrite or inject text after the gate (never allowed, whatever the allow-list says)."""
    out = []
    for node in (workflow or {}).values():
        cls = str(node.get("class_type", "")) if isinstance(node, dict) else ""
        if TEXT_TRANSFORM_NODE_RE.search(cls) and cls not in out and cls not in TRANSFORM_EXEMPT:
            out.append(cls)
    return out


def disallowed_nodes(workflow: dict, extra_allowed: list[str] | tuple = ()) -> list[str]:
    """Every class_type that is not on the allow-list, plus every text-rewriting class. Non-dict nodes count as disallowed."""
    allowed = DEFAULT_ALLOWED_NODES | {str(x) for x in extra_allowed}
    out = []
    for nid, node in (workflow or {}).items():
        cls = str(node.get("class_type", "")) if isinstance(node, dict) else f"<malformed node {nid}>"
        if (cls not in allowed or cls in text_transform_nodes({nid: node})) and cls not in out:
            out.append(cls)
    return out


def text_inputs(workflow: dict) -> list[str]:
    """Every string input that is not exactly a model-file name — prompts, but also anything a custom node might carry."""
    inv = inventory(); out = []
    for _, cls, k, v in _walk_strings(workflow):
        if not v.strip() or is_model_file_value(v, inv):
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


# ---------------------------------------------------------------- uploads (input images) ----------
UPLOADS = os.path.join(STORE, "input", ".aegis-uploads.json")


def _uploads() -> dict:
    try:
        with open(UPLOADS, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {}


def uploads_add(user: str, name: str) -> None:
    with _LOCK:
        u = _uploads(); u[name] = {"user": user, "ts": datetime.now(timezone.utc).isoformat()}
        tmp = UPLOADS + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(u, f)
        os.chmod(tmp, 0o600); os.replace(tmp, UPLOADS)


def uploads_owner(name: str) -> str | None:
    return (_uploads().get(os.path.basename(name)) or {}).get("user")


def uploads_of(user: str) -> list[str]:
    d = os.path.join(STORE, "input")
    return sorted(n for n, v in _uploads().items() if v.get("user") == user and os.path.isfile(os.path.join(d, n)))


def input_refs(workflow: dict) -> list[str]:
    """String inputs that name a file in the input directory (LoadImage etc.)."""
    d = os.path.join(STORE, "input"); out = []
    for _, _, _, v in _walk_strings(workflow):
        b = os.path.basename(v.replace("\\", "/"))
        if b and b != "example.png" and os.path.isfile(os.path.join(d, b)) and b not in out:
            out.append(b)
    return out


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
