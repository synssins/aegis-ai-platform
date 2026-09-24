"""Aegis hub — model browser providers (Hugging Face, CivitAI), thumbnail proxy, download jobs.

Admin-only surface, mounted read-only into the hub next to hub.py. The hub owns identity, CSRF, audit and the
page; this module only talks to the registries and the model store. Rules (docs/designs/portal-and-identity.md,
updated 2026-09-24): NSFW listings are never fetched unless the admin toggle is on; previews are proxied through
the hub (browsers never contact the registries); ingestion accepts .safetensors and .gguf only and verifies the
registry's SHA-256 when it publishes one; CivitAI early-access ("costs Buzz") is flagged on every card.
"""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "aegis-hub/1 (self-hosted model browser)"
THUMB_HOSTS = {"image.civitai.com", "huggingface.co", "cdn-lfs.huggingface.co", "cdn-lfs-us-1.huggingface.co", "cdn-lfs-eu-1.huggingface.co"}
NEXT_HOSTS = {"huggingface.co", "civitai.com"}
SAFE_EXT = (".safetensors", ".gguf")
PICKLE_EXT = (".ckpt", ".pt", ".pth", ".bin", ".pkl")
TYPES = [("image", "Image models"), ("lora", "LoRA"), ("video", "Video"), ("llm", "Language (GGUF)"), ("tts", "Speech"), ("any", "Everything")]
SORTS = [("downloads", "Most downloaded"), ("likes", "Most liked"), ("newest", "Newest")]
COMFY_DIRS = {"Checkpoint": "checkpoints", "LORA": "loras", "LoCon": "loras", "DoRA": "loras", "VAE": "vae", "Controlnet": "controlnet",
              "Upscaler": "upscale_models", "TextualInversion": "embeddings", "MotionModule": "motion", "hf-image": "checkpoints", "hf-lora": "loras"}
STORE = os.environ.get("COMFY_STORE", "/app/comfy-store")


# ---------------------------------------------------------------- HTTP ------------------
def _get(url: str, token: str | None = None, timeout: int = 25, raw: bool = False):
    h = {"User-Agent": UA, "Accept": "application/octet-stream" if raw else "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read()
        return (r.status, r.headers, body) if raw else (r.status, r.headers, json.loads(body.decode()))


def _strip_html(s: str, n: int = 2500) -> str:
    s = re.sub(r"<br\s*/?>|</p>|</li>", "\n", s or "")
    s = html.unescape(re.sub(r"<[^>]+>", "", s))
    s = re.sub(r"\n{3,}", "\n\n", s).strip()
    return s[:n] + ("…" if len(s) > n else "")


def _fmt_size(b: int | float | None) -> str:
    if not b:
        return "?"
    for u in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.1f} {u}" if u != "B" else f"{int(b)} B"
        b /= 1024
    return f"{b:.1f} PB"


def _ext_ok(name: str) -> tuple[bool, str]:
    n = name.lower()
    if n.endswith(SAFE_EXT):
        return True, "ok"
    if n.endswith(PICKLE_EXT):
        return False, "pickle format refused"
    return False, "unsupported format"


# ---------------------------------------------------------------- hardware fit ----------
def fit_badge(size_bytes: int | float | None, cards: list[dict] | dict, kind: str) -> dict:
    """Operational guidance, not a control. Image/video models run on ONE card; a language model may be spread by
    Ollama over every card of a pool. Each card is judged on its own memory (Intel cards are declared, so their free
    memory is approximate)."""
    if isinstance(cards, dict):        # legacy shape {idx: {...}}
        cards = [{"pool": "nvidia", "name": g.get("name", ""), "mem_total": (g.get("mem_used") or 0) + (g.get("mem_free") or 0), "mem_free": g.get("mem_free") or 0} for g in cards.values()]
    if not size_bytes or not cards:
        return {"label": "unknown", "cls": "mut", "why": "no size or no GPU inventory", "cards": []}
    need = size_bytes * (1.20 if kind == "llm" else 1.35) + (1.5 * 2**30 if kind == "llm" else 2.0 * 2**30)
    per = []
    for c in cards:
        tot, free = (c.get("mem_total") or 0) * 2**20, (c.get("mem_free") or 0) * 2**20
        per.append({"card": c.get("name", "?"), "pool": c.get("pool", "?"), "fit": "now" if need <= free else "after unload" if need <= tot else "no"})
    short = lambda n: n.replace("Tesla ", "").replace("Intel(R) Arc(tm) ", "").replace("Arc Pro ", "").replace("NVIDIA ", "")
    now = sorted({short(x["card"]) for x in per if x["fit"] == "now"}); later = sorted({short(x["card"]) for x in per if x["fit"] == "after unload"})
    if now:
        lab, cls = "fits now on " + "/".join(now), "ok"
    elif later:
        lab, cls = "fits on " + "/".join(later) + " after unload", "warn"
    else:
        lab, cls = "won't fit one card", "bad"
        if kind == "llm":
            pools = {}
            for c in cards:
                pools.setdefault(c.get("pool", "?"), []).append((c.get("mem_total") or 0) * 2**20)
            ok = [f"{k} pool ({len(v)}×{_fmt_size(v[0])})" for k, v in pools.items() if sum(v) >= need]
            if ok:
                lab, cls = "spread across " + ", ".join(ok), "warn"
    return {"label": lab, "cls": cls, "why": f"needs ≈{_fmt_size(need)} ({'one card, image/video' if kind != 'llm' else 'per card; Ollama spreads over a pool'})", "cards": per}


# ---------------------------------------------------------------- Hugging Face ----------
HF_TYPE_Q = {"llm": "filter=gguf", "image": "pipeline_tag=text-to-image", "lora": "filter=lora", "video": "pipeline_tag=text-to-video",
             "tts": "pipeline_tag=text-to-speech", "any": ""}
HF_SORT = {"downloads": "downloads", "likes": "likes", "newest": "createdAt"}


def hf_search(q: str, typ: str, sort: str, nsfw: bool, nxt: str | None, token: str | None) -> dict:
    if nxt:
        url = nxt
    else:
        qs = [f"search={urllib.parse.quote(q)}" if q else "", HF_TYPE_Q.get(typ, ""), f"sort={HF_SORT.get(sort, 'downloads')}", "direction=-1", "limit=30"]
        url = "https://huggingface.co/api/models?" + "&".join(x for x in qs if x)
    st, hdr, data = _get(url, token)
    link = hdr.get("Link", "") or ""
    m = re.search(r'<([^>]+)>;\s*rel="next"', link)
    items = []
    for d in data if isinstance(data, list) else []:
        tags = d.get("tags") or []
        adult = "not-for-all-audiences" in tags
        if adult and not nsfw:
            continue
        rid = d.get("id", "")
        items.append({"src": "hf", "id": rid, "name": rid.split("/", 1)[-1], "author": rid.split("/", 1)[0] if "/" in rid else "",
                      "type": d.get("pipeline_tag") or ("gguf" if "gguf" in tags else d.get("library_name") or ""), "tags": tags[:8], "nsfw": adult,
                      "downloads": d.get("downloads", 0), "likes": d.get("likes", 0), "updated": (d.get("createdAt") or "")[:10], "thumb": None,
                      "base": "", "buzz": False, "size": None, "gated": bool(d.get("gated")), "url": f"https://huggingface.co/{rid}"})
    return {"items": items, "next": m.group(1) if m else None}


def hf_detail(repo: str, nsfw: bool, token: str | None, gpus: dict) -> dict:
    st, _, d = _get(f"https://huggingface.co/api/models/{urllib.parse.quote(repo, safe='/')}?blobs=true", token)
    tags = d.get("tags") or []
    files, ggufs = [], []
    for s in d.get("siblings") or []:
        n = s.get("rfilename", ""); sz = s.get("size") or 0; sha = (s.get("lfs") or {}).get("sha256")
        ok, why = _ext_ok(n)
        if not n.lower().endswith(SAFE_EXT + PICKLE_EXT):
            continue
        kind = "llm" if n.lower().endswith(".gguf") else "image"
        f = {"name": n, "size": sz, "size_h": _fmt_size(sz), "sha256": sha, "format": n.rsplit(".", 1)[-1].lower(), "ok": ok, "why": why,
             "fit": fit_badge(sz, gpus, kind), "url": f"https://huggingface.co/{repo}/resolve/main/{urllib.parse.quote(n)}"}
        if kind == "llm":
            q = re.search(r"[-.]((?:IQ|Q|F|BF)\d[A-Z0-9_]*)\.gguf$", n, re.I)
            f["quant"] = q.group(1).upper() if q else None
            ggufs.append(f)
        files.append(f)
    readme = ""
    try:
        _, _, raw = _get(f"https://huggingface.co/{repo}/raw/main/README.md", token, raw=True)
        txt = raw.decode(errors="replace")
        txt = re.sub(r"^---\n.*?\n---\n", "", txt, count=1, flags=re.S)
        readme = txt[:3000] + ("…" if len(txt) > 3000 else "")
    except Exception:  # noqa: BLE001
        pass
    return {"src": "hf", "id": repo, "name": repo, "author": d.get("author", ""), "type": d.get("pipeline_tag") or d.get("library_name") or "",
            "tags": tags[:20], "nsfw": "not-for-all-audiences" in tags, "downloads": d.get("downloads", 0), "likes": d.get("likes", 0),
            "updated": (d.get("lastModified") or "")[:10], "gated": bool(d.get("gated")), "license": (d.get("cardData") or {}).get("license", ""),
            "base": (d.get("cardData") or {}).get("base_model", ""), "description": readme, "images": [], "buzz": False,
            "url": f"https://huggingface.co/{repo}", "files": files, "ollama_pullable": bool(ggufs), "versions": []}


# ---------------------------------------------------------------- CivitAI ---------------
CV_TYPE_Q = {"image": "types=Checkpoint", "lora": "types=LORA&types=LoCon&types=DoRA", "video": "types=Checkpoint&types=LORA&tag=video",
             "llm": None, "tts": None, "any": ""}
CV_SORT = {"downloads": "Most Downloaded", "likes": "Highest Rated", "newest": "Newest"}


def _cv_thumb(images: list, nsfw: bool) -> str | None:
    for im in images or []:
        if (im.get("nsfwLevel") or 1) > 2 and not nsfw:          # PG / PG-13 previews only unless NSFW is on
            continue
        u = im.get("url") or ""
        if not u:
            continue
        u = re.sub(r"/(original=true|width=\d+)[^/]*/", "/width=450,anim=false/", u)
        return u
    return None


def _cv_buzz(v: dict) -> bool:
    return v.get("availability") == "EarlyAccess" or bool(v.get("paidAccess")) or bool(v.get("earlyAccessEndsAt")) or bool(v.get("earlyAccessDeadline"))


def cv_search(q: str, typ: str, sort: str, nsfw: bool, nxt: str | None, token: str | None) -> dict:
    tq = CV_TYPE_Q.get(typ, "")
    if tq is None:
        return {"items": [], "next": None, "note": "CivitAI hosts image/video generation models, not language or speech models."}
    if nxt:
        url = nxt
    else:
        qs = [f"query={urllib.parse.quote(q)}" if q else "", tq, f"sort={urllib.parse.quote(CV_SORT.get(sort, 'Most Downloaded'))}",
              f"nsfw={'true' if nsfw else 'false'}", "limit=30"]
        url = "https://civitai.com/api/v1/models?" + "&".join(x for x in qs if x)
    st, _, data = _get(url, token)
    items = []
    for d in data.get("items", []):
        if d.get("nsfw") and not nsfw:
            continue
        v = (d.get("modelVersions") or [{}])[0]
        pf = next((f for f in v.get("files", []) if f.get("primary")), (v.get("files") or [{}])[0])
        items.append({"src": "civitai", "id": str(d.get("id")), "name": d.get("name", ""), "author": (d.get("creator") or {}).get("username", ""),
                      "type": d.get("type", ""), "tags": (d.get("tags") or [])[:8], "nsfw": bool(d.get("nsfw")),
                      "downloads": (d.get("stats") or {}).get("downloadCount", 0), "likes": (d.get("stats") or {}).get("thumbsUpCount", 0),
                      "updated": (v.get("publishedAt") or "")[:10], "thumb": _cv_thumb(v.get("images"), nsfw), "base": v.get("baseModel", ""),
                      "buzz": any(_cv_buzz(x) for x in d.get("modelVersions") or []), "size": (pf.get("sizeKB") or 0) * 1024,
                      "gated": False, "url": f"https://civitai.com/models/{d.get('id')}"})
    return {"items": items, "next": (data.get("metadata") or {}).get("nextPage")}


def cv_detail(mid: str, nsfw: bool, token: str | None, gpus: dict) -> dict:
    st, _, d = _get(f"https://civitai.com/api/v1/models/{int(mid)}", token)
    versions, images = [], []
    for v in d.get("modelVersions") or []:
        files = []
        for f in v.get("files") or []:
            n = f.get("name", ""); sz = (f.get("sizeKB") or 0) * 1024
            ok, why = _ext_ok(n)
            if f.get("pickleScanResult") not in (None, "Success") or f.get("virusScanResult") not in (None, "Success"):
                ok, why = False, "registry scan not clean"
            files.append({"name": n, "size": sz, "size_h": _fmt_size(sz), "sha256": ((f.get("hashes") or {}).get("SHA256") or "").lower() or None,
                          "format": (f.get("metadata") or {}).get("format", ""), "fp": (f.get("metadata") or {}).get("fp", ""), "ok": ok, "why": why,
                          "fit": fit_badge(sz, gpus, "image"), "url": f.get("downloadUrl"), "file_id": f.get("id"), "primary": bool(f.get("primary"))})
        vi = [im for im in v.get("images") or [] if nsfw or (im.get("nsfwLevel") or 1) <= 2]
        images += [{"thumb": _cv_thumb([im], nsfw), "type": im.get("type", "image"), "w": im.get("width"), "h": im.get("height")} for im in vi[:6]]
        versions.append({"id": v.get("id"), "name": v.get("name", ""), "base": v.get("baseModel", ""), "published": (v.get("publishedAt") or "")[:10],
                         "buzz": _cv_buzz(v), "availability": v.get("availability", "Public"), "trained_words": (v.get("trainedWords") or [])[:12],
                         "files": files, "downloads": (v.get("stats") or {}).get("downloadCount", 0)})
    return {"src": "civitai", "id": str(d.get("id")), "name": d.get("name", ""), "author": (d.get("creator") or {}).get("username", ""),
            "type": d.get("type", ""), "tags": (d.get("tags") or [])[:20], "nsfw": bool(d.get("nsfw")),
            "downloads": (d.get("stats") or {}).get("downloadCount", 0), "likes": (d.get("stats") or {}).get("thumbsUpCount", 0),
            "updated": (versions[0]["published"] if versions else ""), "gated": False, "license": "", "base": versions[0]["base"] if versions else "",
            "description": _strip_html(d.get("description", "")), "images": images[:12], "buzz": any(v["buzz"] for v in versions),
            "url": f"https://civitai.com/models/{d.get('id')}", "files": [], "ollama_pullable": False, "versions": versions,
            "comfy_dir": COMFY_DIRS.get(d.get("type", ""))}


# ---------------------------------------------------------------- thumbnail proxy --------
_THUMBS: dict[str, tuple[str, bytes, float]] = {}
_TL = threading.Lock()


def thumb(url: str) -> tuple[str, bytes] | None:
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    if u.scheme != "https" or u.hostname not in THUMB_HOSTS:
        return None
    with _TL:
        hit = _THUMBS.get(url)
    if hit and time.time() - hit[2] < 3600:
        return hit[0], hit[1]
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "image/*"})
        with urllib.request.urlopen(req, timeout=20) as r:
            ct = r.headers.get("Content-Type", "image/jpeg").split(";")[0]
            if not ct.startswith("image/"):
                return None
            data = r.read(6 * 2**20 + 1)
            if len(data) > 6 * 2**20:
                return None
    except Exception:  # noqa: BLE001
        return None
    with _TL:
        if len(_THUMBS) > 300:
            for k in list(_THUMBS)[:100]:
                _THUMBS.pop(k, None)
        _THUMBS[url] = (ct, data, time.time())
    return ct, data


# ---------------------------------------------------------------- download jobs ---------
DL: dict[str, dict] = {}
_DL = threading.Lock()


def start_download(src: str, url: str, subdir: str, filename: str, sha256: str | None, size: int | None, token: str | None, audit) -> tuple[str | None, str]:
    """Stream a registry file into the ComfyUI store. Refuses pickles and unknown formats, verifies SHA-256 when
    the registry publishes one, writes to .part and renames only on success. Returns (job id, message)."""
    name = os.path.basename(filename).replace("..", "")
    ok, why = _ext_ok(name)
    if not ok:
        return None, f"{name}: {why}"
    if subdir not in set(COMFY_DIRS.values()):
        return None, "unknown destination"
    host = urllib.parse.urlsplit(url).hostname or ""
    if not (host.endswith("civitai.com") or host.endswith("huggingface.co")):
        return None, "download host not allowed"
    dest_dir = os.path.join(STORE, subdir); os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, name)
    if os.path.exists(dest):
        return None, f"{subdir}/{name} already exists"
    jid = hashlib.sha1(f"{url}{time.time()}".encode()).hexdigest()[:8]
    with _DL:
        DL[jid] = {"src": src, "file": f"{subdir}/{name}", "status": "starting", "done": 0, "total": size or 0, "started": time.time(), "finished": False, "error": None}

    def run():
        part = dest + ".part"; h = hashlib.sha256(); got = 0
        try:
            hdr = {"User-Agent": UA}
            if token:
                hdr["Authorization"] = f"Bearer {token}"
            req = urllib.request.Request(url, headers=hdr)
            with urllib.request.urlopen(req, timeout=60) as r, open(part, "wb") as f:
                total = int(r.headers.get("Content-Length") or 0) or (size or 0)
                cd = r.headers.get("Content-Disposition", "")
                with _DL:
                    DL[jid].update(status="downloading", total=total)
                while True:
                    chunk = r.read(1 << 20)
                    if not chunk:
                        break
                    f.write(chunk); h.update(chunk); got += len(chunk)
                    with _DL:
                        DL[jid]["done"] = got
            digest = h.hexdigest()
            if sha256 and digest != sha256.lower():
                os.unlink(part); raise ValueError(f"SHA-256 mismatch (got {digest[:12]}…, registry {sha256[:12]}…)")
            os.replace(part, dest); os.chmod(dest, 0o644)
            with _DL:
                DL[jid].update(status="done", finished=True, sha256=digest)
            audit("model_downloaded", source=src, file=f"{subdir}/{name}", bytes=got, sha256=digest, verified=bool(sha256))
        except Exception as e:  # noqa: BLE001
            try:
                os.unlink(part)
            except FileNotFoundError:
                pass
            err = str(e)[:200]
            if isinstance(e, urllib.error.HTTPError) and e.code in (401, 403):
                err += " — the registry wants an API key/token (Registry settings)" + (" or this version is early access (Buzz)" if src == "civitai" else " or the repository is gated")
            with _DL:
                DL[jid].update(status="failed", finished=True, error=err)
            audit("model_download_failed", source=src, file=f"{subdir}/{name}", error=str(e)[:200])

    threading.Thread(target=run, daemon=True).start()
    return jid, f"Download started: {subdir}/{name}"


def jobs() -> list[dict]:
    with _DL:
        return [{"id": k, **v} for k, v in sorted(DL.items(), key=lambda kv: kv[1]["started"], reverse=True)][:20]
