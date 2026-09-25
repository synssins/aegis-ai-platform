"""Offline regression tests for caddy/hub (hub.py + imagegate.py): runs the real request handler on a local port.
Needs Python 3.12 (hub.py uses 3.12 f-string syntax) and argon2-cffi + cryptography."""
import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix="hub-test-")
os.environ["HUB_SECRET_KEY"] = "t" * 48
os.environ["COMFY_STORE"] = os.path.join(TMP, "store")
os.environ["GALLERY_DIR"] = os.path.join(TMP, "gallery")
sys.path.insert(0, os.path.join(ROOT, "caddy", "hub"))
import hub  # noqa: E402
import imagegate  # noqa: E402

for name in ("STATE_DIR", "AUDIT_DIR"):
    setattr(hub, name, os.path.join(TMP, name.lower()))
    os.makedirs(getattr(hub, name), exist_ok=True)
hub.USERS_FILE = os.path.join(hub.STATE_DIR, "users.json")
hub.DEVICES_FILE = os.path.join(hub.STATE_DIR, "devices.json")
hub.STATE_FILE = os.path.join(hub.STATE_DIR, "hub.json")
hub.HUB_AUDIT = os.path.join(hub.AUDIT_DIR, "hub-audit.jsonl")
hub.VETO_AUDIT = os.path.join(hub.AUDIT_DIR, "veto-audit.jsonl")
hub.POLICY_FILE = os.path.join(TMP, "veto-policy.json")
for d in ("checkpoints", "input", "temp", "output"):
    os.makedirs(os.path.join(os.environ["COMFY_STORE"], d), exist_ok=True)
open(os.path.join(os.environ["COMFY_STORE"], "checkpoints", "RealVisXL_V5.0.safetensors"), "w").close()

MARK = "ZZ_MARKER_ZZ"


def user(flags, **extra):
    return {"hash": hub.PH.hash("Correct-Horse-9-battery"), "totp": None, "totp_last": 0, "must_change": False, "created": hub.now(),
            "updated": hub.now(), "session_epoch": 0, "flags": {**hub.USER_FLAGS, **flags}, **extra}


hub.save_users({
    "admin": user({"admin": True, "chat": True, "images": True, "speech": True}),
    "imgs": user({"images": True}),
    "chatonly": user({}),
    "speaker": user({"speech": True}),
    "invited": user({"images": True, "speech": True}, must_change=True, invite=True, invite_expires=time.time() + 86400),
})


def cookie(u, limited=False):
    tok = hub.sign({"kind": "session", "u": u, "epoch": 0, "exp": time.time() + 600, "ttl": "24h", "n": "x", "fp": "", **({"limited": True} if limited else {})})
    return f"aegis_hub={tok}"


class Server:
    def __enter__(self):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), hub.Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return self

    def get(self, path, ck=None):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=10)
        c.request("GET", path, headers={"Cookie": ck} if ck else {})
        r = c.getresponse(); body = r.read(); c.close()
        return r.status, body

    def __exit__(self, *a):
        self.srv.shutdown()


class ForwardAuth(unittest.TestCase):
    """H3 / M5: the forward_auth endpoints answer 200 ONLY for a fully signed-in session holding the grant."""
    def test_matrix(self):
        cases = [
            ("/hub/authz/comfy", "imgs", False, 200),
            ("/hub/authz/comfy", "admin", False, 200),
            ("/hub/authz/comfy", "chatonly", False, 403),
            ("/hub/authz/comfy", "invited", True, 403),     # invite-code-only session (no MFA) — was 200 before the fix
            ("/hub/authz/comfy", "imgs", True, 403),        # any limited session
            ("/hub/authz/speech", "speaker", False, 200),
            ("/hub/authz/speech", "imgs", False, 403),
            ("/hub/authz/speech", "invited", True, 403),
        ]
        with Server() as s:
            for path, u, limited, want in cases:
                with self.subTest(path=path, user=u, limited=limited):
                    st, _ = s.get(path, cookie(u, limited))
                    self.assertEqual(st, want)
            for path in ("/hub/authz/comfy", "/hub/authz/speech"):
                st, _ = s.get(path)                              # no session -> redirect (not 2xx)
                self.assertFalse(200 <= st < 300, path)


class ImagePromptGate(unittest.TestCase):
    """H4: text ending in a model filename is checked; oversize text is refused; text-rewriting nodes are refused."""
    def test_filename_suffix_no_longer_hides_text(self):
        wf = {"1": {"class_type": "CheckpointLoaderSimple", "inputs": {"ckpt_name": "RealVisXL_V5.0.safetensors"}},
              "2": {"class_type": "CLIPTextEncode", "inputs": {"text": MARK + " /RealVisXL_V5.0.safetensors"}},
              "3": {"class_type": "CLIPTextEncode", "inputs": {"text": MARK + " \\RealVisXL_V5.0.safetensors"}}}
        texts = imagegate.text_inputs(wf)
        self.assertEqual(sum(MARK in t for t in texts), 2)
        self.assertNotIn("RealVisXL_V5.0.safetensors", texts)            # the real model field is still recognised
        self.assertIn("RealVisXL_V5.0.safetensors", imagegate.file_refs(wf))

    def test_oversize_text_refused_not_truncated(self):
        ok, why = hub.gate_text("imgs", ["x " * 30000, MARK])
        self.assertFalse(ok)
        self.assertIn("at most", why)

    def test_node_allowlist(self):
        bad = ["StringConcatenate", "ConcatStrings", "JoinStrings", "easy promptConcat", "CR Combine Prompt", "SDXLPromptStyler",
               "Load Text File", "LoadPromptsFromFile", "OllamaGenerate", "Florence2Run", "Text Concatenate", "PrimitiveEvil", "RegexReplace"]
        for cls in bad:
            with self.subTest(cls=cls):
                self.assertEqual(imagegate.disallowed_nodes({"1": {"class_type": cls}}), [cls])
        self.assertEqual(imagegate.disallowed_nodes({"1": {"class_type": "ConcatStrings"}}, ["ConcatStrings"]), ["ConcatStrings"],
                         "an administrator cannot allow a text-rewriting node")
        self.assertEqual(imagegate.disallowed_nodes({"1": {"class_type": "MyUpscaler"}}, ["MyUpscaler"]), [])
        ok = {str(i): {"class_type": c} for i, c in enumerate(["CLIPTextEncode", "VAEEncode", "ConditioningConcat", "PrimitiveString", "KSampler", "SaveImage"])}
        self.assertEqual(imagegate.disallowed_nodes(ok), [])

    def test_text_transform_nodes_detected(self):
        wf = {"1": {"class_type": "StringReplace", "inputs": {"string": "a", "find": "b", "replace": "c"}},
              "2": {"class_type": "PrimitiveStringMultiline", "inputs": {"value": "hello"}},
              "3": {"class_type": "CLIPTextEncode", "inputs": {"text": ["1", 0]}}}
        self.assertEqual(imagegate.text_transform_nodes(wf), ["StringReplace"])

    def test_aegis_workflows_pass_node_check(self):
        import glob
        for f in glob.glob(os.path.join(ROOT, "comfyui", "user", "default", "workflows", "Aegis", "*.json")):
            wf = json.load(open(f))
            api = {str(n["id"]): {"class_type": n.get("type")} for n in wf.get("nodes", [])} if "nodes" in wf else wf
            self.assertEqual(imagegate.disallowed_nodes(api), [], os.path.basename(f))


class ZeroRetentionHub(unittest.TestCase):
    """Zero retention: no evidence store, no export route, no snippets; old policy keys are dropped."""
    def test_no_evidence_surface(self):
        for name in ("act_evidence_handoff", "evidence_index", "_expire_evidence", "EVIDENCE_KEY", "SNIPPETS", "HANDOFF_DIR"):
            self.assertFalse(hasattr(hub, name), name)
        self.assertNotIn("/hub/api/evidence/handoff", hub.ACTIONS)
        for name in ("seal_evidence", "phash"):
            self.assertFalse(hasattr(imagegate, name), name)
        with Server() as s:
            st, _ = s.get("/hub/evidence/download/20260101T000000Z-deadbeef", cookie("admin"))
            self.assertEqual(st, 404)

    def test_legacy_policy_keys_dropped(self):
        with open(hub.POLICY_FILE, "w") as f:
            json.dump({"audit": {"store_snippet": True}, "retention": {"evidence": {"enabled": True}}}, f)
        p = hub.policy()
        self.assertNotIn("audit", p)
        self.assertNotIn("evidence", p["retention"])
        self.assertTrue(p["categories"]["S4"]["block"])
        os.unlink(hub.POLICY_FILE)

    def test_default_classifier_is_8b(self):
        self.assertEqual(hub.DEFAULT_POLICY["guard"]["model"], "llama-guard3:8b")

    def test_portal_chat_does_not_store_before_answer(self):
        js = hub.CHAT_HTML
        send = js[js.index("async function send("):js.index("$(\"#cform\").onsubmit")]
        self.assertLess(send.index("fetch(\"/chat/api/stream\""), send.index("save()"), "nothing may be saved before the request")
        self.assertIn("vetoed", send)
        self.assertIn("splice", send)


if __name__ == "__main__":
    unittest.main()
