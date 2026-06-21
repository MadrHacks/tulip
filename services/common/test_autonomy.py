import unittest

from autonomy import (
    Level,
    Decision,
    authority,
    AuditEntry,
    AuditLog,
    gate,
)


class AuthorityTruthTableTest(unittest.TestCase):
    def test_auto_invariants_ok_no_kill_is_only_allow(self):
        d = authority("offense", "fire", Level.AUTO, True, False)
        self.assertEqual(d, Decision(True, False, "auto: invariants hold"))
        self.assertTrue(d.allow)
        self.assertFalse(d.require_human)

    def test_kill_switch_always_denies_even_auto(self):
        for level in Level:
            for inv in (True, False):
                d = authority("defense", "deploy-rule", level, inv, kill_switch=True)
                self.assertFalse(d.allow)
                self.assertFalse(d.require_human)
                self.assertEqual(d.reason, "kill-switch engaged")

    def test_invariant_failure_always_denies_even_auto(self):
        for level in Level:
            d = authority("offense", "fan-out", level, False, kill_switch=False)
            self.assertFalse(d.allow)
            self.assertFalse(d.require_human)
            self.assertEqual(d.reason, "invariant failed: fan-out")

    def test_kill_switch_takes_precedence_over_invariant(self):
        d = authority("offense", "arm", Level.AUTO, False, kill_switch=True)
        self.assertEqual(d.reason, "kill-switch engaged")

    def test_manual_never_allows_requires_human(self):
        d = authority("defense", "enable-rule", Level.MANUAL, True)
        self.assertEqual(d, Decision(False, True, "manual: human must act"))

    def test_assist_never_allows_requires_human(self):
        d = authority("offense", "arm", Level.ASSIST, True)
        self.assertEqual(d, Decision(False, True, "assist: proposed, awaiting human"))

    def test_allow_only_true_for_auto_invariants_no_kill(self):
        for level in Level:
            for inv in (True, False):
                for kill in (False, True):
                    d = authority("c", "a", level, inv, kill)
                    expected = level is Level.AUTO and inv and not kill
                    self.assertEqual(d.allow, expected, (level, inv, kill))


class AuditLogTest(unittest.TestCase):
    def test_records_n_in_order(self):
        log = AuditLog()
        for i in range(5):
            d = authority("offense", f"act{i}", Level.AUTO, True)
            log.record("offense", f"act{i}", Level.AUTO, d, subject=f"s{i}")
        es = log.entries()
        self.assertEqual(len(es), 5)
        self.assertEqual([e.action for e in es], [f"act{i}" for i in range(5)])
        self.assertEqual([e.subject for e in es], [f"s{i}" for i in range(5)])

    def test_entries_is_immutable_view(self):
        log = AuditLog()
        d = authority("offense", "fire", Level.AUTO, True)
        log.record("offense", "fire", Level.AUTO, d)
        es = log.entries()
        self.assertIsInstance(es, tuple)
        # tuple cannot be mutated
        with self.assertRaises((AttributeError, TypeError)):
            es.append(None)  # type: ignore[attr-defined]
        # and entries are frozen dataclasses
        with self.assertRaises(dataclasses.FrozenInstanceError):
            es[0].allowed = False  # type: ignore[misc]
        self.assertEqual(len(log.entries()), 1)

    def test_mutating_snapshot_does_not_change_log(self):
        log = AuditLog()
        d = authority("offense", "fire", Level.AUTO, True)
        log.record("offense", "fire", Level.AUTO, d)
        snapshot = list(log.entries())
        snapshot.clear()
        snapshot.append("junk")
        self.assertEqual(len(log.entries()), 1)

    def test_records_both_denied_and_allowed(self):
        log = AuditLog()
        denied = authority("defense", "deploy-rule", Level.MANUAL, True)
        allowed = authority("offense", "fire", Level.AUTO, True)
        log.record("defense", "deploy-rule", Level.MANUAL, denied)
        log.record("offense", "fire", Level.AUTO, allowed)
        es = log.entries()
        self.assertEqual(len(es), 2)
        self.assertFalse(es[0].allowed)
        self.assertTrue(es[0].require_human)
        self.assertTrue(es[1].allowed)
        self.assertFalse(es[1].require_human)

    def test_record_returns_entry_with_stamp(self):
        log = AuditLog()
        d = authority("offense", "arm", Level.AUTO, True)
        entry = log.record("offense", "arm", Level.AUTO, d, subject="box7")
        self.assertIsInstance(entry, AuditEntry)
        self.assertGreater(entry.ts, 0)
        self.assertEqual(entry.level, "auto")
        self.assertEqual(entry.subject, "box7")
        self.assertIs(entry, log.entries()[0])


class GateTest(unittest.TestCase):
    def test_gate_records_and_returns_consistently(self):
        log = AuditLog()
        d = gate(log, "offense", "fire", Level.AUTO, True, subject="target1")
        self.assertEqual(d, authority("offense", "fire", Level.AUTO, True))
        es = log.entries()
        self.assertEqual(len(es), 1)
        self.assertEqual(es[0].allowed, d.allow)
        self.assertEqual(es[0].require_human, d.require_human)
        self.assertEqual(es[0].reason, d.reason)
        self.assertEqual(es[0].subject, "target1")

    def test_gate_kill_switch(self):
        log = AuditLog()
        d = gate(log, "offense", "fire", Level.AUTO, True, kill_switch=True)
        self.assertFalse(d.allow)
        self.assertEqual(d.reason, "kill-switch engaged")
        self.assertEqual(len(log.entries()), 1)

    def test_gate_denied_still_recorded(self):
        log = AuditLog()
        gate(log, "defense", "enable-rule", Level.ASSIST, True)
        self.assertEqual(len(log.entries()), 1)
        self.assertFalse(log.entries()[0].allowed)


import dataclasses  # noqa: E402  (used in immutability assertion above)


if __name__ == "__main__":
    unittest.main()
