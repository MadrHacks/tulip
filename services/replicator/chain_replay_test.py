import base64
import unittest

from chain_replay import replay_chain


def _const_seg(raw: bytes) -> dict:
    return {"const": base64.b64encode(raw).decode()}


def _make_plan():
    step0_template = {
        "segments": [_const_seg(b"LOGIN user="), {"var": True}, _const_seg(b"\n")],
        "slots": [{"type": "const", "charclass": "alnum", "min_len": 1,
                   "max_len": 8, "example": "admin"}],
    }
    step1_template = {
        "segments": [_const_seg(b"ACTION token="), {"var": True}, _const_seg(b" do=flag\n")],
        "slots": [{"type": "const", "charclass": "hex", "min_len": 1,
                   "max_len": 64, "example": "PLACEHOLDER"}],
    }
    return {
        "steps": [
            {"template": step0_template, "service": "auth", "port": 1337},
            {"template": step1_template, "service": "auth", "port": 1337},
        ],
        "links": [
            {"producer_step": 0, "consumer_step": 1,
             "extract": r"token=([0-9A-F]+)", "inject_slot": 0},
        ],
    }


class ChainReplayTest(unittest.TestCase):
    def test_happy_path_carries_token(self):
        plan = _make_plan()
        seen = []

        def fake_send(req: bytes, service: str, port: int) -> bytes:
            seen.append((req, service, port))
            if len(seen) == 1:
                self.assertEqual(service, "auth")
                self.assertIn(b"LOGIN user=admin", req)
                return b"OK Set-Cookie: token=DEADBEEFCAFE123456; path=/"
            self.assertIn(b"DEADBEEFCAFE123456", req)
            self.assertIn(b"ACTION token=DEADBEEFCAFE123456", req)
            return b"flag{w0rk1ng_ch41n}"

        result = replay_chain(plan, fake_send)

        self.assertTrue(result["ok"])
        self.assertIsNone(result["error"])
        self.assertEqual(result["steps_run"], 2)
        self.assertEqual(len(seen), 2)
        self.assertEqual(result["carried"][0], b"DEADBEEFCAFE123456")
        self.assertTrue(any(b"flag{" in r for r in result["responses"]))

    def test_extract_failure_aborts_before_consumer(self):
        plan = _make_plan()
        seen = []

        def fake_send(req: bytes, service: str, port: int) -> bytes:
            seen.append((req, service, port))
            if len(seen) == 1:
                return b"OK but no token here"
            raise AssertionError("step 1 send must not be called after extract failure")

        result = replay_chain(plan, fake_send)

        self.assertFalse(result["ok"])
        self.assertIsNotNone(result["error"])
        self.assertIn("did not match", result["error"])
        self.assertEqual(result["steps_run"], 1)
        self.assertEqual(len(seen), 1)
        self.assertEqual(result["carried"], {})


if __name__ == "__main__":
    unittest.main()
