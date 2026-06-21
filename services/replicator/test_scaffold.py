import base64
import unittest

from scaffold import render_scaffold


def _const(s):
    return {"const": base64.b64encode(s).decode("ascii")}


class RenderScaffoldTest(unittest.TestCase):
    def _flagid_template(self):
        return {
            "segments": [
                _const(b"GET /note/"),
                {"var": True},
                _const(b" HTTP/1.1\r\n\r\n"),
            ],
            "slots": [
                {"type": "flagid", "charclass": "alnum",
                 "min_len": 8, "max_len": 8, "example": "abc12345"},
            ],
        }

    def test_basic_flagid_scaffold(self):
        result = render_scaffold(self._flagid_template(),
                                 service="notes", host="10.60.1.1", port=8080)
        self.assertTrue(result)
        self.assertIn("def exploit(", result)
        self.assertIn("re-fetch the flagId", result)  # flagid TODO
        self.assertIn("sock.sendall(request)", result)  # socket send

    def test_emitted_skeleton_compiles(self):
        result = render_scaffold(self._flagid_template(),
                                 service="notes", host="10.60.1.1", port=8080)
        # The crucial property: the emitted skeleton is valid Python.
        compile(result, "<scaffold>", "exec")

    def test_const_bytes_present(self):
        result = render_scaffold(self._flagid_template())
        self.assertIn("GET /note/", result)
        self.assertIn(" HTTP/1.1", result)

    def test_random_hex_slot_uses_secrets(self):
        template = {
            "segments": [_const(b"TOKEN="), {"var": True}, _const(b"\n")],
            "slots": [
                {"type": "random", "charclass": "hex",
                 "min_len": 16, "max_len": 16, "example": "deadbeefdeadbeef"},
            ],
        }
        result = render_scaffold(template)
        self.assertIn("secrets.choice", result)  # secrets-based generator line
        self.assertIn("0123456789abcdef", result)  # hex alphabet
        compile(result, "<scaffold>", "exec")

    def test_flag_and_unknown_slots_get_todo(self):
        template = {
            "segments": [{"var": True}, {"var": True}],
            "slots": [
                {"type": "flag"},
                {"type": "unknown"},
            ],
        }
        result = render_scaffold(template)
        self.assertEqual(result.count('b"..."'), 2)
        compile(result, "<scaffold>", "exec")

    def test_empty_template_still_compiles(self):
        result = render_scaffold({})
        self.assertIn("def exploit(", result)
        compile(result, "<scaffold>", "exec")


if __name__ == "__main__":
    unittest.main()
