import base64
import unittest

from interactive_replay import replay_interactive


def const_seg(s: bytes) -> dict:
    return {"const": base64.b64encode(s).decode()}


class FakeConn:
    """Records what was sent; returns the scripted responses in order."""

    def __init__(self, recvs):
        self.recvs = list(recvs)
        self.sent = []
        self.markers = []

    def send(self, data: bytes) -> None:
        self.sent.append(data)

    def recv_until(self, marker):
        self.markers.append(marker)
        return self.recvs.pop(0)


class TestInteractiveReplay(unittest.TestCase):
    def test_login_then_use_carried_token(self):
        plan = {
            "steps": [
                {"template": {"segments": [const_seg(b"login\n")], "slots": []}, "expect": "token="},
                {"template": {"segments": [const_seg(b"use "), {"var": True}, const_seg(b"\n")],
                              "slots": [{"type": "const"}]}, "expect": "FLAG"},
            ],
            "links": [{"producer_step": 0, "consumer_step": 1, "extract": "token=([A-Z0-9]+)", "inject_slot": 0}],
        }
        conn = FakeConn([b"ok token=ABC123 >", b"FLAG{deadbeef}"])
        r = replay_interactive(plan, conn)
        self.assertTrue(r["ok"], r["error"])
        self.assertEqual(conn.sent[0], b"login\n")
        self.assertEqual(conn.sent[1], b"use ABC123\n")          # carried token injected mid-session
        self.assertEqual(conn.markers, [b"token=", b"FLAG"])     # read until each step's prompt
        self.assertIn(b"FLAG{deadbeef}", r["responses"][1])

    def test_flagid_slot_filled(self):
        plan = {
            "steps": [
                {"template": {"segments": [const_seg(b"get "), {"var": True}, const_seg(b"\n")],
                              "slots": [{"type": "flagid"}]}, "expect": None},
            ],
            "links": [],
        }
        conn = FakeConn([b"here is your FLAG{x}"])
        r = replay_interactive(plan, conn, flagids=[b"FID-42"])
        self.assertTrue(r["ok"], r["error"])
        self.assertEqual(conn.sent[0], b"get FID-42\n")          # flagid slot filled from the fetched id

    def test_extract_failure_reported(self):
        plan = {
            "steps": [
                {"template": {"segments": [const_seg(b"a")], "slots": []}, "expect": None},
                {"template": {"segments": [const_seg(b"b"), {"var": True}], "slots": [{"type": "const"}]},
                 "expect": None},
            ],
            "links": [{"producer_step": 0, "consumer_step": 1, "extract": "NOPE([0-9]+)", "inject_slot": 0}],
        }
        conn = FakeConn([b"no match here", b"unused"])
        r = replay_interactive(plan, conn)
        self.assertFalse(r["ok"])
        self.assertIn("extract", r["error"])
        self.assertEqual(len(conn.sent), 1)                      # stopped after the failing producer step


if __name__ == "__main__":
    unittest.main()
