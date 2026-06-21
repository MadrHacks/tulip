import unittest

from deploy import PatchEngine


class FakeFiregex:
    def __init__(self):
        self.regexes = {}
        self.enabled = set()
        self._next = 1

    def add_regex(self, service_id, regex, mode="B", active=False, is_case_sensitive=False):
        rid = self._next
        self._next += 1
        self.regexes[rid] = regex
        if active:
            self.enabled.add(rid)
        return rid

    def set_regex_active(self, rid, active):
        (self.enabled.add if active else self.enabled.discard)(rid)
        return True

    def delete_regex(self, rid):
        self.regexes.pop(rid, None)
        self.enabled.discard(rid)
        return True


class TestPatchEngine(unittest.TestCase):
    def test_propose_pushes_inactive(self):
        fx = FakeFiregex()
        pe = PatchEngine(fx, armed=True)
        rid = pe.propose("cluster:svc:1", [b"__EXPLOIT__"], [b"benign request"], service_id="s1")
        self.assertIsNotNone(rid)
        self.assertIn(rid, fx.regexes)
        self.assertNotIn(rid, fx.enabled)  # created INACTIVE

    def test_propose_refused_when_anchor_in_benign(self):
        fx = FakeFiregex()
        pe = PatchEngine(fx, armed=True)
        rid = pe.propose("cluster:svc:2", [b"/status?id="], [b"checker GET /status?id=1"], service_id="s1")
        self.assertIsNone(rid)
        self.assertEqual(fx.regexes, {})  # nothing pushed

    def test_arm_requires_armed(self):
        fx = FakeFiregex()
        disarmed = PatchEngine(fx, armed=False)
        rid = disarmed.propose("c", [b"__EXPLOIT__"], [b"x"], "s1")
        self.assertFalse(disarmed.arm_rule("c"))
        self.assertNotIn(rid, fx.enabled)

        armed = PatchEngine(fx, armed=True)
        armed.deployed["c"] = rid
        self.assertTrue(armed.arm_rule("c"))
        self.assertIn(rid, fx.enabled)

    def test_rollback_disables_and_deletes(self):
        fx = FakeFiregex()
        pe = PatchEngine(fx, armed=True)
        rid = pe.propose("c", [b"__EXPLOIT__"], [b"x"], "s1")
        pe.arm_rule("c")
        self.assertTrue(pe.rollback("c"))
        self.assertNotIn(rid, fx.regexes)
        self.assertNotIn(rid, fx.enabled)
        self.assertNotIn("c", pe.deployed)


if __name__ == "__main__":
    unittest.main()
