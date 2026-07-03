import base64
import unittest

from instantiate import (
    fill_slots,
    gen_value,
    instantiate,
    is_allowed_target,
    target_allowlist,
)


def _b64(s: bytes) -> str:
    return base64.b64encode(s).decode()


class TestInstantiate(unittest.TestCase):
    def test_rebuild_get_request(self):
        template = {
            "segments": [
                {"const": _b64(b"GET /note/")},
                {"var": True},
                {"const": _b64(b" HTTP")},
            ],
            "slots": [{"type": "random", "charclass": "hex"}],
        }
        out = instantiate(template, [b"abc123"])
        self.assertEqual(out, b"GET /note/abc123 HTTP")

    def test_wrong_slot_values_length_raises(self):
        template = {
            "segments": [{"const": _b64(b"X")}, {"var": True}],
            "slots": [{"type": "random"}],
        }
        with self.assertRaises(ValueError):
            instantiate(template, [])
        with self.assertRaises(ValueError):
            instantiate(template, [b"a", b"b"])


class TestGenValue(unittest.TestCase):
    def test_random_hex_length_and_alphabet(self):
        slot = {"type": "random", "charclass": "hex", "min_len": 10, "max_len": 16}
        for _ in range(200):
            v = gen_value(slot)
            self.assertIsInstance(v, bytes)
            self.assertTrue(10 <= len(v) <= 16)
            self.assertTrue(all(c in b"0123456789abcdef" for c in v))

    def test_random_charclasses(self):
        cases = {
            "base64url": set(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
            ),
            "alnum": set(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            ),
        }
        for charclass, allowed in cases.items():
            slot = {
                "type": "random",
                "charclass": charclass,
                "min_len": 8,
                "max_len": 8,
            }
            for _ in range(100):
                v = gen_value(slot).decode()
                self.assertEqual(len(v), 8)
                self.assertTrue(set(v) <= allowed)

    def test_random_uuid(self):
        import uuid

        v = gen_value({"type": "random", "charclass": "uuid"})
        uuid.UUID(v.decode())  # raises if not a valid uuid

    def test_random_length_fallback(self):
        v = gen_value({"type": "random", "charclass": "hex", "example": "deadbeef"})
        self.assertEqual(len(v), 8)
        v2 = gen_value({"type": "random", "charclass": "hex"})
        self.assertEqual(len(v2), 8)

    def test_const_and_unknown_return_example(self):
        self.assertEqual(gen_value({"type": "const", "example": "hello"}), b"hello")
        self.assertEqual(gen_value({"type": "unknown", "example": "x"}), b"x")
        self.assertEqual(gen_value({"type": "const"}), b"")

    def test_flag_and_flagid_empty(self):
        self.assertEqual(gen_value({"type": "flag"}), b"")
        self.assertEqual(gen_value({"type": "flagid"}), b"")


class TestFillSlots(unittest.TestCase):
    def test_flagid_pops_and_flag_stays_empty(self):
        template = {
            "slots": [
                {"type": "const", "example": "A"},
                {"type": "flagid"},
                {"type": "flag"},
                {"type": "flagid"},
            ]
        }
        out = fill_slots(template, flagids=[b"id1", b"id2"])
        self.assertEqual(out, [b"A", b"id1", b"", b"id2"])

    def test_flagid_exhausted_raises(self):
        template = {"slots": [{"type": "flagid"}, {"type": "flagid"}]}
        with self.assertRaises(ValueError):
            fill_slots(template, flagids=[b"only-one"])


class TestTargetAllowlist(unittest.TestCase):
    def test_excludes_our_team(self):
        our = 7
        targets = target_allowlist(our, team_count=10, ip_format="10.60.{}.1", nop_team=0)
        indices = [i for i, _ in targets]
        self.assertNotIn(our, indices)
        self.assertEqual(targets[0], (0, "10.60.0.1"))  # nop included
        for i in range(0, 11):
            if i != our:
                self.assertIn(i, indices)
        self.assertEqual(len(indices), 10)  # 0..10 is 11 entries minus our team

    def test_ip_formatting(self):
        targets = target_allowlist(0, team_count=3, ip_format="10.60.{}.1", nop_team=0)
        self.assertEqual(
            targets,
            [(1, "10.60.1.1"), (2, "10.60.2.1"), (3, "10.60.3.1")],
        )

    def test_nop_team_present(self):
        nop = 0
        targets = target_allowlist(5, team_count=8, ip_format="10.0.{}.1", nop_team=nop)
        self.assertIn(nop, [i for i, _ in targets])

    def test_our_team_never_present_for_any_id(self):
        for our in range(0, 12):
            targets = target_allowlist(
                our, team_count=11, ip_format="10.60.{}.1", nop_team=0
            )
            self.assertNotIn(our, [i for i, _ in targets])

    def test_is_allowed_target_guard(self):
        self.assertFalse(is_allowed_target(7, 7))
        self.assertTrue(is_allowed_target(8, 7))
        self.assertTrue(is_allowed_target(0, 7))


if __name__ == "__main__":
    unittest.main()


class TestOwnTeamFailClosed(unittest.TestCase):
    def test_unknown_own_team_refuses_all(self):
        from instantiate import is_allowed_target, target_allowlist
        self.assertFalse(is_allowed_target(0, -1))
        self.assertFalse(is_allowed_target(5, -1))
        # An unknown own team must fire at NOBODY, not everybody.
        self.assertEqual(target_allowlist(-1, 30, "10.60.{}.1", 0), [])

    def test_known_own_team_excluded_nop_included(self):
        from instantiate import target_allowlist
        ts = target_allowlist(36, 42, "10.60.{}.1", 0)
        self.assertTrue(all(t != 36 for t, _ in ts))   # never our own team
        self.assertTrue(any(t == 0 for t, _ in ts))    # NOP still a target
