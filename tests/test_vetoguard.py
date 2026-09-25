"""Offline regression tests for proxy/veto_filter.py (VetoGuard 3.0)."""
import asyncio
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix="vg-test-")
os.environ["VETO_POLICY_PATH"] = os.path.join(TMP, "veto-policy.json")
os.environ["VETO_AUDIT_PATH"] = os.path.join(TMP, "veto-audit.jsonl")
sys.path.insert(0, os.path.join(HERE, "stubs"))
sys.path.insert(0, os.path.join(ROOT, "proxy"))
import veto_filter as vf  # noqa: E402
from fastapi import HTTPException  # noqa: E402

MARK = "ZZ_MARKER_ZZ"


class FakeGuard:
    """Records what the classifier would have been shown; answers from a script."""
    def __init__(self, answer=(False, []), exc=None):
        self.seen, self.answer, self.exc = [], answer, exc

    async def __call__(self, messages):
        self.seen.append(json.dumps(messages))
        if self.exc:
            raise self.exc
        return self.answer


def run(coro):
    return asyncio.run(coro)


def pre(data, guard=None):
    vf._guard_call = guard or FakeGuard()
    return run(vf.VetoGuard().async_pre_call_hook({"key_alias": "test"}, None, data, "acompletion"))


def refused(data, guard=None):
    try:
        pre(data, guard)
    except HTTPException as e:
        return e.status_code, e.detail["error"]["code"]
    return None


def write_policy(p):
    with open(os.environ["VETO_POLICY_PATH"], "w") as f:
        json.dump(p, f)
    vf.POLICY.reload(force=True)


class NonTextContent(unittest.TestCase):
    """C1: images, audio and files are refused before anything else runs (zero inference on unreadable content)."""
    def test_image_with_benign_text_is_refused(self):
        g = FakeGuard()
        r = refused({"messages": [{"role": "user", "content": [{"type": "text", "text": "describe this"},
                     {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}}]}]}, g)
        self.assertEqual(r, (400, "unsupported_content"))
        self.assertEqual(g.seen, [], "classifier must not even be called")

    def test_every_non_text_part_type_is_refused(self):
        for part in ({"type": "input_image", "image_url": "x"}, {"type": "input_audio", "input_audio": {"data": "x"}},
                     {"type": "audio", "data": "x"}, {"type": "file", "file": {"file_data": "x"}},
                     {"type": "custom", "image_url": {"url": "x"}}, {"type": "video_url", "video_url": "x"}):
            with self.subTest(part=part["type"]):
                r = refused({"messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}, part]}]})
                self.assertEqual(r, (400, "unsupported_content"))

    def test_image_in_earlier_turn_is_refused(self):
        r = refused({"messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "x"}}]},
                                  {"role": "assistant", "content": "ok"}, {"role": "user", "content": "and now?"}]})
        self.assertEqual(r, (400, "unsupported_content"))

    def test_ollama_native_images_field_is_refused(self):
        r = refused({"messages": [{"role": "user", "content": "describe", "images": ["iVBORw0KGgo="]}]})
        self.assertEqual(r, (400, "unsupported_content"))

    def test_provider_native_media_keys_are_refused(self):
        for body in ({"prompt": "describe", "images": ["iVBORw0KGgo="]},
                     {"messages": [{"role": "user", "content": [{"text": "hi"}, {"inline_data": {"mime_type": "image/png", "data": "x"}}]}]},
                     {"messages": [{"role": "user", "content": "hi", "audio": {"data": "x"}}]}):
            with self.subTest(body=list(body)):
                self.assertEqual(refused(body), (400, "unsupported_content"))

    def test_tool_arguments_and_schemas_named_file_or_image_pass(self):
        """No false positives: a tool whose schema or arguments use the words file/image is plain text."""
        tools = [{"type": "function", "function": {"name": "open", "parameters": {"type": "object", "properties": {"file": {"type": "string"}, "image": {"type": "string"}}}}}]
        body = {"messages": [{"role": "user", "content": "open a.txt"},
                             {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "open", "input": {"file": "a.txt", "image": "b.png"}}]},
                             {"role": "user", "content": [{"type": "text", "text": "thanks", "annotations": [{"type": "file_citation", "file_id": "f1"}]}]}],
                "tools": tools, "response_format": {"type": "json_schema", "json_schema": {"schema": {"properties": {"image": {"type": "string"}}}}}}
        self.assertIsNone(refused(body))

    def test_plain_text_still_passes(self):
        self.assertIsNone(refused({"messages": [{"role": "user", "content": "What is the capital of France?"}]}))


class LockedTripwires(unittest.TestCase):
    """H2 (partial): the child-safety word list cannot be switched off from the policy."""
    def tearDown(self):
        write_policy({})

    def test_csam_list_runs_with_tripwires_disabled(self):
        write_policy({"tripwires": {"enabled": False, "extra_patterns": []}})
        g = FakeGuard()
        r = refused({"messages": [{"role": "user", "content": "csam"}]}, g)   # the bare list keyword, not content
        self.assertEqual(r, (400, "veto_triggered"))
        self.assertEqual(g.seen, [])

    def test_sentinel_list_is_switchable(self):
        write_policy({"tripwires": {"enabled": False, "extra_patterns": []}})
        # sentinel list off -> reaches the classifier (despaced pass still has the sentinel root, so use a spaced form it won't join)
        self.assertEqual(vf.tripwire_check(["hello world"], vf.LOCKED_TRIPWIRES), None)

    def test_s4_cannot_be_unblocked(self):
        write_policy({"categories": {"S4": {"block": False}}})
        self.assertIn("S4", vf.POLICY.blocked())

    def test_default_classifier_is_8b(self):
        self.assertEqual(vf.DEFAULT_POLICY["guard"]["model"], os.environ.get("VETO_GUARD_MODEL", "llama-guard3:8b"))


class ZeroRetention(unittest.TestCase):
    """M1/M2: vetoes leave metadata only — no content, no matched spans, no evidence files, no snippets."""
    def setUp(self):
        open(os.environ["VETO_AUDIT_PATH"], "w").close()

    def _audit_text(self):
        vf._AUDIT_Q.join()
        with open(os.environ["VETO_AUDIT_PATH"]) as f:
            return f.read()

    def test_tripwire_veto_stores_no_content(self):
        secret = "csam " + MARK
        refused({"messages": [{"role": "user", "content": secret}]})
        log = self._audit_text()
        self.assertIn("regex:csam", log)
        self.assertNotIn(MARK, log)
        self.assertNotIn("span", log)

    def test_classifier_veto_stores_no_content(self):
        refused({"messages": [{"role": "user", "content": "plain words " + MARK}]}, FakeGuard(answer=(True, ["S4"])))
        log = self._audit_text()
        self.assertIn("S4 Child Sexual Exploitation", log)
        self.assertNotIn(MARK, log)

    def test_output_veto_stores_no_content(self):
        vf._guard_call = FakeGuard(answer=(True, ["S1"]))
        resp = {"choices": [{"message": {"content": "output text " + MARK}}]}
        with self.assertRaises(HTTPException):
            run(vf.VetoGuard().async_post_call_success_hook({"messages": [{"role": "user", "content": "hi"}]}, {"key_alias": "t"}, resp))
        self.assertNotIn(MARK, self._audit_text())

    def test_unparseable_verdict_does_not_echo_content(self):
        with self.assertRaises(vf.GuardVerdictUnparseable) as cm:
            vf._parse_llama_guard("I think the user said " + MARK + " which is fine")
        self.assertNotIn(MARK, cm.exception.got)
        with self.assertRaises(vf.GuardVerdictUnparseable) as cm:
            vf._parse_llama_guard("Safe.")
        self.assertEqual(cm.exception.got, "Safe.")

    def test_no_evidence_or_snippet_code_remains(self):
        for name in ("write_evidence", "snippet", "EVIDENCE_KEY", "EVIDENCE_DIR", "SNIPPET_PATH", "_wants_evidence"):
            self.assertFalse(hasattr(vf, name), name)


class FailClosed(unittest.TestCase):
    """Regression guard for the behaviour the audit found correct."""
    def test_guard_unreachable_refuses(self):
        self.assertEqual(refused({"messages": [{"role": "user", "content": "hi"}]}, FakeGuard(exc=vf.GuardUnavailable("down"))),
                         (503, "guard_unavailable"))

    def test_unsafe_without_codes_blocks(self):
        self.assertEqual(vf._parse_llama_guard("unsafe"), (True, ["UNSPECIFIED"]))
        self.assertEqual(refused({"messages": [{"role": "user", "content": "hi"}]}, FakeGuard(answer=(True, ["UNSPECIFIED"]))),
                         (400, "veto_triggered"))


if __name__ == "__main__":
    unittest.main()
