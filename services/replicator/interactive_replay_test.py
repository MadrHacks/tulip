import base64
import re
import unittest

from interactive_replay import replay_interactive


def const_seg(s: bytes) -> dict:
    return {"const": base64.b64encode(s).decode()}


VAR = {"var": True}


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

    def test_selfref_reuses_earlier_sent_slot(self):
        # register mints a random credential; login must reuse that SAME sent
        # value (a selfref link), not a freshly generated one, or the session
        # would not authenticate.
        plan = {
            "steps": [
                {"template": {"segments": [const_seg(b"register "), {"var": True}, const_seg(b"\n")],
                              "slots": [{"type": "random", "charclass": "alnum", "min_len": 8, "max_len": 8}]},
                 "expect": "ok"},
                {"template": {"segments": [const_seg(b"login "), {"var": True}, const_seg(b"\n")],
                              "slots": [{"type": "selfref"}]}, "expect": "FLAG"},
            ],
            "links": [{"kind": "selfref", "producer_step": 0, "producer_slot": 0,
                       "consumer_step": 1, "inject_slot": 0, "extract": ""}],
        }
        conn = FakeConn([b"registered ok", b"FLAG{y}"])
        r = replay_interactive(plan, conn)
        self.assertTrue(r["ok"], r["error"])
        user_reg = conn.sent[0][len(b"register "):-1]     # the random creds sent at register
        user_login = conn.sent[1][len(b"login "):-1]       # the creds sent at login
        self.assertEqual(user_reg, user_login)             # selfref copied the earlier sent value
        self.assertTrue(len(user_reg) == 8)

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


class TestHeldOutReconstruction(unittest.TestCase):
    """Replay-execution fidelity, modeled on the reference engine's held-out test:
    feed a target's captured server bytes as a MOCK server, GRANT only a fresh
    flagId + fresh nonces, and require the outgoing client bytes to reconstruct
    exactly — with the MIRROR value DERIVED from an earlier server response (not
    granted), the SELFREF creds reused verbatim, and any LENGTH recomputed."""

    def test_boomthrow_register_login_boomerang(self):
        # The genuine aviation EXFIL shape: POST /api/register (fresh random
        # creds) -> POST /api/login (reuse those creds, server mints a session
        # token) -> GET /api/boomerang?id=<flagId> with the token mirrored into
        # the Authorization header. FLAGID fresh, MIRROR derived, SELFREF reused,
        # RANDOM generated once and carried.
        plan = {
            "service": "boomthrow", "port": 8080,
            "steps": [
                {"template": {"segments": [
                    const_seg(b"POST /api/register HTTP/1.1\r\nHost: t\r\n"
                              b"Content-Type: application/json\r\n\r\n{\"username\":\""),
                    VAR, const_seg(b"\",\"password\":\""), VAR, const_seg(b"\"}")],
                    "slots": [
                        {"type": "random", "charclass": "alnum", "min_len": 12, "max_len": 12},
                        {"type": "random", "charclass": "alnum", "min_len": 12, "max_len": 12}]},
                 "expect": "\r\n\r\n"},
                {"template": {"segments": [
                    const_seg(b"POST /api/login HTTP/1.1\r\nHost: t\r\n"
                              b"Content-Type: application/json\r\n\r\n{\"username\":\""),
                    VAR, const_seg(b"\",\"password\":\""), VAR, const_seg(b"\"}")],
                    "slots": [{"type": "selfref"}, {"type": "selfref"}]},
                 "expect": "\r\n\r\n"},
                {"template": {"segments": [
                    const_seg(b"GET /api/boomerang?id="), VAR,
                    const_seg(b" HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer "), VAR,
                    const_seg(b"\r\n\r\n")],
                    "slots": [
                        {"type": "flagid"},
                        {"type": "mirror", "source_step": 1, "transform": "identity",
                         "mirror_prefix": base64.b64encode(b"{\"token\":\"").decode(),
                         "mirror_suffix": base64.b64encode(b"\"}").decode()}]},
                 "expect": None},
            ],
            "links": [
                {"kind": "selfref", "producer_step": 0, "producer_slot": 0,
                 "consumer_step": 1, "inject_slot": 0, "extract": ""},
                {"kind": "selfref", "producer_step": 0, "producer_slot": 1,
                 "consumer_step": 1, "inject_slot": 1, "extract": ""},
                {"kind": "mirror", "producer_step": 1, "consumer_step": 2,
                 "extract": r"(?s)\{\"token\":\"(.*?)\"\}", "inject_slot": 1,
                 "transform": "identity"},
            ],
        }
        # A target's captured server bytes: registration ack, a login that mints a
        # session token, and the flag-bearing boomerang read.
        conn = FakeConn([
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"registered\"}",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"token\":\"SESSIONTOKEN_abc123\"}\n",
            b"HTTP/1.1 200 OK\r\n\r\n{\"boomerang\":\"flag{st0len_thr0w}\"}",
        ])
        r = replay_interactive(plan, conn, flagids=[b"FRESH-FID-777"])
        self.assertTrue(r["ok"], r["error"])
        self.assertEqual(len(conn.sent), 3)

        creds_re = re.compile(rb'\{"username":"([^"]+)","password":"([^"]+)"\}')
        reg = creds_re.search(conn.sent[0])
        log = creds_re.search(conn.sent[1])
        self.assertIsNotNone(reg)
        self.assertIsNotNone(log)
        # RANDOM generated at register, of the requested width.
        self.assertEqual(len(reg.group(1)), 12)
        self.assertEqual(len(reg.group(2)), 12)
        # SELFREF: login reused the SAME creds the register step invented.
        self.assertEqual(reg.group(1), log.group(1))
        self.assertEqual(reg.group(2), log.group(2))
        # FLAGID: the freshly granted id (not any value from the captured bytes).
        self.assertIn(b"GET /api/boomerang?id=FRESH-FID-777 HTTP/1.1", conn.sent[2])
        # MIRROR: the token was DERIVED from step 1's response, not granted.
        self.assertIn(b"Authorization: Bearer SESSIONTOKEN_abc123\r\n\r\n", conn.sent[2])
        # and the flag came back on the retrieval turn.
        self.assertIn(b"flag{st0len_thr0w}", r["responses"][2])

    def test_mirror_transform_base64_decodes_server_representation(self):
        # A base64-wrapped mirror: the server hands out a base64 token, the client
        # must send the DECODED value (transform b64encode: from_server decodes).
        plan = {
            "service": "svc", "port": 9,
            "steps": [
                {"template": {"segments": [const_seg(b"GET /token HTTP/1.1\r\nHost: t\r\n\r\n")],
                              "slots": []}, "expect": None},
                {"template": {"segments": [const_seg(b"GET /use?tok="), VAR,
                                           const_seg(b" HTTP/1.1\r\nHost: t\r\n\r\n")],
                              "slots": [{"type": "mirror", "source_step": 0, "transform": "b64encode",
                                         "mirror_prefix": base64.b64encode(b"\"data\":\"").decode(),
                                         "mirror_suffix": base64.b64encode(b"\"").decode()}]},
                 "expect": None},
            ],
            "links": [
                {"kind": "mirror", "producer_step": 0, "consumer_step": 1,
                 "extract": r"(?s)\"data\":\"(.*?)\"", "inject_slot": 0, "transform": "b64encode"},
            ],
        }
        # U0VDUkVUX1RPS0VO == base64("SECRET_TOKEN"); the client must send the decode.
        conn = FakeConn([
            b"HTTP/1.1 200 OK\r\n\r\n{\"data\":\"U0VDUkVUX1RPS0VO\"}",
            b"HTTP/1.1 200 OK\r\n\r\nflag{ok}",
        ])
        r = replay_interactive(plan, conn)
        self.assertTrue(r["ok"], r["error"])
        self.assertIn(b"GET /use?tok=SECRET_TOKEN HTTP/1.1", conn.sent[1])

    def test_length_slot_is_recomputed_over_body(self):
        # A Content-Length driven by a LENGTH slot must equal the assembled body's
        # byte length (derived, never granted), even though the body carries a
        # fresh random of a length the captured build never saw.
        plan = {
            "service": "svc", "port": 9,
            "steps": [
                {"template": {"segments": [
                    const_seg(b"POST /submit HTTP/1.1\r\nHost: t\r\nContent-Length: "), VAR,
                    const_seg(b"\r\nContent-Type: application/json\r\n\r\n{\"name\":\""), VAR,
                    const_seg(b"\"}")],
                    "slots": [{"type": "length"},
                              {"type": "random", "charclass": "alnum", "min_len": 7, "max_len": 7}]},
                 "expect": None},
            ],
            "links": [],
        }
        conn = FakeConn([b"HTTP/1.1 200 OK\r\n\r\nflag{len}"])
        r = replay_interactive(plan, conn)
        self.assertTrue(r["ok"], r["error"])
        sent = conn.sent[0]
        cl = re.search(rb"Content-Length: (\d+)\r\n", sent)
        self.assertIsNotNone(cl)
        body = sent.split(b"\r\n\r\n", 1)[1]
        self.assertEqual(int(cl.group(1)), len(body))       # recomputed, matches the real body
        self.assertTrue(body.startswith(b"{\"name\":\""))
        self.assertTrue(body.endswith(b"\"}"))
        self.assertEqual(int(cl.group(1)), 18)              # 9 + 7 + 2 bytes

    def test_grants_override_random_and_flagid_per_slot(self):
        # The held-out fidelity path GRANTS the held-out instance's OWN
        # unpredictable RANDOM/flagId values per (step, slot) — like the reference
        # engine — while MIRROR/SELFREF/LENGTH stay DERIVED. Here a plan whose
        # small-sample classifier tagged the register username FLAGID (a second
        # flagid slot in an earlier step) must still reconstruct byte-exact: a flat
        # flagids list cannot (fill_slots restarts it per step), but per-slot grants
        # can.
        plan = {
            "service": "svc", "port": 9,
            "steps": [
                {"template": {"segments": [const_seg(b"register user="), VAR,
                                           const_seg(b" pw="), VAR, const_seg(b"\n")],
                              "slots": [{"type": "flagid"},
                                        {"type": "random", "charclass": "alnum",
                                         "min_len": 8, "max_len": 8}]}, "expect": "ok"},
                {"template": {"segments": [const_seg(b"get "), VAR, const_seg(b"\n")],
                              "slots": [{"type": "flagid"}]}, "expect": "FLAG"},
            ],
            "links": [],
        }
        conn = FakeConn([b"ok", b"FLAG{x}"])
        grants = {
            0: {0: b"HELDOUT_USERNAME", 1: b"pw012345"},  # username-as-flagid + random
            1: {0: b"REAL-SELECTOR-42"},                   # the genuine retrieval flagId
        }
        # flagids padded so fill_slots (restarts per step) never runs out; grants override.
        r = replay_interactive(plan, conn, flagids=[b""], grants=grants)
        self.assertTrue(r["ok"], r["error"])
        self.assertEqual(conn.sent[0], b"register user=HELDOUT_USERNAME pw=pw012345\n")
        self.assertEqual(conn.sent[1], b"get REAL-SELECTOR-42\n")  # distinct value, right step

    def test_grants_default_off_is_pure_random(self):
        # Without grants the RANDOM path is unchanged (fresh nonce of the asked width).
        plan = {
            "service": "svc", "port": 9,
            "steps": [
                {"template": {"segments": [const_seg(b"n="), VAR, const_seg(b"\n")],
                              "slots": [{"type": "random", "charclass": "alnum",
                                         "min_len": 6, "max_len": 6}]}, "expect": None},
            ],
            "links": [],
        }
        conn = FakeConn([b"ok"])
        r = replay_interactive(plan, conn)
        self.assertTrue(r["ok"], r["error"])
        body = conn.sent[0]
        self.assertTrue(body.startswith(b"n=") and body.endswith(b"\n"))
        self.assertEqual(len(body), len(b"n=") + 6 + len(b"\n"))

    def test_computed_slot_refuses_to_fire(self):
        # A COMPUTED slot (crypto/session token the engine could not prove
        # regenerable) must gate the plan: fail closed, send nothing.
        plan = {
            "service": "svc", "port": 9,
            "steps": [
                {"template": {"segments": [const_seg(b"GET /x?sig="), VAR,
                                           const_seg(b" HTTP/1.1\r\n\r\n")],
                              "slots": [{"type": "computed", "example": "deadbeefcafe1234"}]},
                 "expect": None},
            ],
            "links": [],
        }
        conn = FakeConn([b"unused"])
        r = replay_interactive(plan, conn)
        self.assertFalse(r["ok"])
        self.assertIn("COMPUTED", r["error"])
        self.assertEqual(conn.sent, [])                     # never touched the wire

    def test_unreproducible_plan_not_fired(self):
        # A plan the engine gated as Unreproducible must never open the connection,
        # even if it (defensively) still carries steps.
        plan = {
            "service": "svc", "port": 9, "unreproducible": True,
            "reason": "COMPUTED-required-slot (1, crypto)",
            "steps": [
                {"template": {"segments": [const_seg(b"GET / HTTP/1.1\r\n\r\n")], "slots": []},
                 "expect": None},
            ],
            "links": [],
        }
        conn = FakeConn([b"unused"])
        r = replay_interactive(plan, conn)
        self.assertFalse(r["ok"])
        self.assertIn("unreproducible", r["error"])
        self.assertIn("crypto", r["error"])
        self.assertEqual(conn.sent, [])                     # gated before any send


if __name__ == "__main__":
    unittest.main()
