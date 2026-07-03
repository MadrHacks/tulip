import socket
import unittest

from actuate import Config, Replicator, SocketConn
from autopilot import AutoConfig, AutoPilot


class FakeSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = []
        self.closed = False

    def sendall(self, d):
        self.sent.append(d)

    def recv(self, _n):
        if self.chunks:
            return self.chunks.pop(0)
        raise socket.timeout()

    def settimeout(self, _t):
        pass

    def close(self):
        self.closed = True


class TestSocketConn(unittest.TestCase):
    def test_recv_until_splits_on_marker_and_buffers_remainder(self):
        c = SocketConn(FakeSocket([b"hello wor", b"ld PROMPT> more"]))
        out = c.recv_until(b"PROMPT> ")
        self.assertEqual(out, b"hello world PROMPT> ")
        self.assertEqual(c.buf, b"more")  # kept for the next step

    def test_recv_until_none_drains_until_idle(self):
        c = SocketConn(FakeSocket([b"aaa", b"bbb"]))
        self.assertEqual(c.recv_until(None), b"aaabbb")

    def test_recv_until_stops_on_eof(self):
        c = SocketConn(FakeSocket([b"partial ", b""]))  # empty chunk = EOF
        self.assertEqual(c.recv_until(b"NEVER"), b"partial ")


def _cfg():
    return Config(team_id=36, ip_format="10.60.{}.1", flag_regex="FLAG",
                  flagids_url="", farm_url="", farm_token="")


class TestInteractiveGating(unittest.TestCase):
    def _plan(self):
        return {"steps": [{"template": {"segments": [], "slots": []}}], "port": 1}

    def test_disarmed_session_emits_nothing(self):
        r = Replicator(_cfg(), armed=False)
        self.assertEqual(r.replay_session(self._plan(), "s", 0), {"ok": False, "armed": False, "flags": []})

    def test_session_refuses_own_team(self):
        r = Replicator(_cfg(), armed=True)
        with self.assertRaises(ValueError):
            r.replay_session(self._plan(), "s", 36)

    def test_fanout_session_requires_nop_proof(self):
        r = Replicator(_cfg(), armed=True)
        with self.assertRaises(ValueError):
            r.fanout_session(self._plan(), "unproven", [(1, "10.60.1.1")])


class TestAutopilotKindDispatch(unittest.TestCase):
    def test_interactive_candidate_routes_to_session_methods(self):
        calls = []

        class Rep:
            def nop_proof_session(self, plan, sploit, nop_team):
                calls.append(("proof_session", sploit))
                return {"flags": ["FLAG"]}

            def replay_session(self, plan, sploit, team):
                calls.append(("replay_session", sploit, team))
                return {"flags": ["FLAG"]}

            def nop_proof(self, **k):
                calls.append(("proof_template",))
                return []

            def replicate(self, *a):
                calls.append(("replicate",))
                return []

        cands = lambda: [{"sploit": "e1", "kind": "interactive",
                          "plan": {"steps": [{}]}, "service": "svc", "port": 1}]
        p = AutoPilot(Rep(), cands, lambda: [(1, "10.60.1.1")],
                      AutoConfig(nop_team=0, tick_start=0.0, tick_duration=120.0, auto_fanout=True), lambda: 0.0)
        p.armed = True
        p.step()
        self.assertIn(("proof_session", "e1"), calls)
        self.assertIn(("replay_session", "e1", 1), calls)
        self.assertNotIn(("proof_template",), calls)   # never touched the single-flow path


if __name__ == "__main__":
    unittest.main()
