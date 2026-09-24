#!/usr/bin/env python3
"""Generate the pre-built Aegis workflows (ComfyUI UI format) into comfyui/user/default/workflows/Aegis/.

Run from the repo root after adding or changing a workflow; commit the JSON. The generator keeps node/link
bookkeeping consistent so the files load cleanly in the ComfyUI workflow browser. Models referenced must be in
the store (Hub → Models → Image model store) and classified for the users who will run them.

Workflows:
  photoreal-txt2img        RealVisXL 5 (SDXL) text-to-image, 1024², DPM++ 2M Karras.
  car-photo-refine         img2img refinement of an uploaded car photo, low denoise so geometry is kept.
  upscale-4x-accurate      4x-UltraSharpV2 model upscale, no diffusion pass — lines and arcs stay where they are.
  upscale-2x-supersampled  4x model upscale then Lanczos to 2x (supersampling): the most accurate 2x we can do.
  upscale-then-refine      4x model upscale, then a very low-denoise SDXL pass for texture only (optional; may soften).
"""
import json
import os
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "comfyui", "user", "default", "workflows", "Aegis")
SDXL = "RealVisXL_V5.0_fp16.safetensors"
UPS = "4x-UltraSharpV2.safetensors"

# node type -> (inputs [(name, type)], outputs [(name, type)]) for the core nodes we use
DEFS = {
    "CheckpointLoaderSimple": ([], [("MODEL", "MODEL"), ("CLIP", "CLIP"), ("VAE", "VAE")]),
    "CLIPTextEncode": ([("clip", "CLIP")], [("CONDITIONING", "CONDITIONING")]),
    "EmptyLatentImage": ([], [("LATENT", "LATENT")]),
    "KSampler": ([("model", "MODEL"), ("positive", "CONDITIONING"), ("negative", "CONDITIONING"), ("latent_image", "LATENT")], [("LATENT", "LATENT")]),
    "VAEDecode": ([("samples", "LATENT"), ("vae", "VAE")], [("IMAGE", "IMAGE")]),
    "VAEEncode": ([("pixels", "IMAGE"), ("vae", "VAE")], [("LATENT", "LATENT")]),
    "SaveImage": ([("images", "IMAGE")], []),
    "LoadImage": ([], [("IMAGE", "IMAGE"), ("MASK", "MASK")]),
    "UpscaleModelLoader": ([], [("UPSCALE_MODEL", "UPSCALE_MODEL")]),
    "ImageUpscaleWithModel": ([("upscale_model", "UPSCALE_MODEL"), ("image", "IMAGE")], [("IMAGE", "IMAGE")]),
    "ImageScaleBy": ([("image", "IMAGE")], [("IMAGE", "IMAGE")]),
}


class WF:
    def __init__(self):
        self.nodes, self.links, self.nid, self.lid = [], [], 0, 0

    def add(self, typ, pos, widgets, title=None):
        ins, outs = DEFS[typ]; self.nid += 1
        n = {"id": self.nid, "type": typ, "pos": list(pos), "size": [315, 100 + 24 * (len(ins) + len(widgets))], "flags": {}, "order": self.nid - 1, "mode": 0,
             "inputs": [{"name": a, "type": b, "link": None} for a, b in ins], "outputs": [{"name": a, "type": b, "links": [], "slot_index": i} for i, (a, b) in enumerate(outs)],
             "properties": {"Node name for S&R": typ}, "widgets_values": list(widgets)}
        if title:
            n["title"] = title
        self.nodes.append(n)
        return n

    def link(self, src, slot, dst, name):
        self.lid += 1
        typ = src["outputs"][slot]["type"]
        src["outputs"][slot]["links"].append(self.lid)
        inp = next(i for i in dst["inputs"] if i["name"] == name); inp["link"] = self.lid
        self.links.append([self.lid, src["id"], slot, dst["id"], dst["inputs"].index(inp), typ])

    def dump(self, name, note):
        os.makedirs(OUT, exist_ok=True)
        doc = {"last_node_id": self.nid, "last_link_id": self.lid, "nodes": self.nodes, "links": self.links, "groups": [],
               "config": {}, "extra": {"aegis": note, "ds": {"scale": 0.8, "offset": [0, 0]}}, "version": 0.4}
        with open(os.path.join(OUT, name + ".json"), "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
        print("wrote", os.path.relpath(os.path.join(OUT, name + ".json")))


NEG = "blurry, lowres, watermark, text, deformed, extra wheels, bad geometry, jpeg artifacts"


def photoreal_txt2img():
    w = WF()
    ck = w.add("CheckpointLoaderSimple", (60, 200), [SDXL])
    pos = w.add("CLIPTextEncode", (440, 120), ["photorealistic photo of a modern sports car on a coastal road at golden hour, sharp focus, 35mm, high detail"], "Positive prompt")
    neg = w.add("CLIPTextEncode", (440, 360), [NEG], "Negative prompt")
    lat = w.add("EmptyLatentImage", (440, 600), [1024, 1024, 1])
    ks = w.add("KSampler", (820, 200), [0, "randomize", 30, 5.0, "dpmpp_2m", "karras", 1.0])
    dec = w.add("VAEDecode", (1200, 200), [])
    sv = w.add("SaveImage", (1480, 200), ["aegis-photoreal"])
    w.link(ck, 1, pos, "clip"); w.link(ck, 1, neg, "clip"); w.link(ck, 0, ks, "model"); w.link(pos, 0, ks, "positive"); w.link(neg, 0, ks, "negative"); w.link(lat, 0, ks, "latent_image")
    w.link(ks, 0, dec, "samples"); w.link(ck, 2, dec, "vae"); w.link(dec, 0, sv, "images")
    w.dump("Aegis - Photoreal txt2img (RealVisXL 5)", "SDXL photoreal baseline. 1024x1024, 30 steps, CFG 5, DPM++ 2M Karras.")


def car_photo_refine():
    w = WF()
    ck = w.add("CheckpointLoaderSimple", (60, 200), [SDXL])
    src = w.add("LoadImage", (60, 520), ["example.png", "image"], "Your car photo (upload)")
    enc = w.add("VAEEncode", (440, 560), [])
    pos = w.add("CLIPTextEncode", (440, 120), ["photorealistic professional car photograph, clean paint, accurate reflections, correct proportions, sharp detail, natural lighting"], "Positive prompt")
    neg = w.add("CLIPTextEncode", (440, 340), [NEG + ", changed body shape, different car"], "Negative prompt")
    ks = w.add("KSampler", (820, 200), [0, "randomize", 28, 4.5, "dpmpp_2m", "karras", 0.35], "Refine (denoise 0.35 keeps geometry)")
    dec = w.add("VAEDecode", (1200, 200), [])
    sv = w.add("SaveImage", (1480, 200), ["aegis-car-refine"])
    w.link(ck, 1, pos, "clip"); w.link(ck, 1, neg, "clip"); w.link(src, 0, enc, "pixels"); w.link(ck, 2, enc, "vae")
    w.link(ck, 0, ks, "model"); w.link(pos, 0, ks, "positive"); w.link(neg, 0, ks, "negative"); w.link(enc, 0, ks, "latent_image")
    w.link(ks, 0, dec, "samples"); w.link(ck, 2, dec, "vae"); w.link(dec, 0, sv, "images")
    w.dump("Aegis - Car photo refine (img2img)", "Upload a car photo, refine paint/reflections/detail. Denoise 0.35: raise for more change, lower (0.2) to keep the exact shape. Resize the input to ~1024 on the long side first for SDXL.")


def upscale_4x():
    w = WF()
    src = w.add("LoadImage", (60, 200), ["example.png", "image"], "Image to upscale (upload)")
    um = w.add("UpscaleModelLoader", (60, 480), [UPS])
    up = w.add("ImageUpscaleWithModel", (440, 200), [], "4x model upscale — no diffusion, lines stay put")
    sv = w.add("SaveImage", (820, 200), ["aegis-upscale4x"])
    w.link(um, 0, up, "upscale_model"); w.link(src, 0, up, "image"); w.link(up, 0, sv, "images")
    w.dump("Aegis - Upscale 4x accurate (UltraSharpV2)", "Pure model upscale (ESRGAN-class). Deterministic, no hallucination, no wavy lines: geometry is preserved. Use for line art, CAD, product shots.")


def upscale_2x_supersampled():
    w = WF()
    src = w.add("LoadImage", (60, 200), ["example.png", "image"], "Image to upscale (upload)")
    um = w.add("UpscaleModelLoader", (60, 480), [UPS])
    up = w.add("ImageUpscaleWithModel", (440, 200), [], "4x model upscale")
    ds = w.add("ImageScaleBy", (820, 200), ["lanczos", 0.5], "Lanczos to 2x (supersampling)")
    sv = w.add("SaveImage", (1200, 200), ["aegis-upscale2x"])
    w.link(um, 0, up, "upscale_model"); w.link(src, 0, up, "image"); w.link(up, 0, ds, "image"); w.link(ds, 0, sv, "images")
    w.dump("Aegis - Upscale 2x supersampled (most accurate)", "4x model upscale then Lanczos down to 2x. Supersampling gives straighter edges and smoother arcs than a native 2x pass.")


def upscale_then_refine():
    w = WF()
    ck = w.add("CheckpointLoaderSimple", (60, 60), [SDXL])
    src = w.add("LoadImage", (60, 380), ["example.png", "image"], "Image (upload)")
    um = w.add("UpscaleModelLoader", (60, 660), [UPS])
    up = w.add("ImageUpscaleWithModel", (440, 420), [], "4x model upscale")
    ds = w.add("ImageScaleBy", (820, 420), ["lanczos", 0.5], "to 2x")
    enc = w.add("VAEEncode", (1200, 420), [])
    pos = w.add("CLIPTextEncode", (440, 60), ["high detail, sharp, photorealistic, same image"], "Positive prompt")
    neg = w.add("CLIPTextEncode", (440, 240), [NEG], "Negative prompt")
    ks = w.add("KSampler", (1580, 120), [0, "randomize", 20, 4.0, "dpmpp_2m", "karras", 0.15], "Texture pass — denoise 0.15 only")
    dec = w.add("VAEDecode", (1960, 120), [])
    sv = w.add("SaveImage", (2240, 120), ["aegis-upscale-refined"])
    w.link(um, 0, up, "upscale_model"); w.link(src, 0, up, "image"); w.link(up, 0, ds, "image"); w.link(ds, 0, enc, "pixels"); w.link(ck, 2, enc, "vae")
    w.link(ck, 1, pos, "clip"); w.link(ck, 1, neg, "clip"); w.link(ck, 0, ks, "model"); w.link(pos, 0, ks, "positive"); w.link(neg, 0, ks, "negative"); w.link(enc, 0, ks, "latent_image")
    w.link(ks, 0, dec, "samples"); w.link(ck, 2, dec, "vae"); w.link(dec, 0, sv, "images")
    w.dump("Aegis - Upscale then refine (optional texture pass)", "After the accurate upscale, a diffusion pass at denoise 0.15 adds micro-texture. It CAN bend fine lines — use the pure upscale when accuracy matters more than texture. Needs ~1 min on a B60 for 2048².")


if __name__ == "__main__":
    for fn in (photoreal_txt2img, car_photo_refine, upscale_4x, upscale_2x_supersampled, upscale_then_refine):
        fn()
    sys.exit(0)
