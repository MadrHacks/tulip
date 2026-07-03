import unittest

from autopilot import AutoPilot, AutoConfig


class FakeReplicator:
    def __init__(self, nop_ok=True, fire_raises=False):
        self.nop_calls = []
        self.fire_calls = []
        self.nop_ok = nop_ok
        self.fire_raises = fire_raises

    def nop_proof(self, template, sploit, service, port, nop_team):
        self.nop_calls.append(sploit)
        return ["FLAG"] if self.nop_ok else []

    def replicate(self, template, sploit, service, port, team):
        if self.fire_raises:
            raise RuntimeError("boom")
        self.fire_calls.append((sploit, team))
        return ["FLAG"]


def candidates(sploits):
    return lambda: [{"sploit": s, "template": {}, "service": "svc", "port": 1} for s in sploits]


def targets(teams):
    return lambda: [(t, f"10.60.{t}.1") for t in teams]


class Clock:
    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t


def pilot(rep, sploits, teams, clock, **cfg):
    c = AutoConfig(nop_team=0, tick_start=0.0, tick_duration=120.0, **cfg)
    return AutoPilot(rep, candidates(sploits), targets(teams), c, clock)


class TestAutoPilotSafety(unittest.TestCase):
    def test_disarmed_never_fires(self):
        rep = FakeReplicator()
        p = pilot(rep, ["e1"], [1, 2, 3], Clock())
        p.step()  # armed defaults to False
        self.assertEqual(rep.fire_calls, [])
        self.assertEqual(rep.nop_calls, [])

    def test_nop_gate_blocks_unproven_fanout(self):
        rep = FakeReplicator(nop_ok=False)  # NOP never captures a flag
        p = pilot(rep, ["e1"], [1, 2, 3], Clock())
        p.armed = True
        p.step()
        self.assertEqual(rep.nop_calls, ["e1"])  # tried NOP
        self.assertEqual(rep.fire_calls, [])      # but never fanned out

    def test_dedup_once_per_team_per_tick(self):
        rep = FakeReplicator()
        p = pilot(rep, ["e1"], [1, 2, 3], Clock())
        p.armed = True
        p.step()
        p.step()  # same tick again
        self.assertEqual(sorted(rep.fire_calls), [("e1", 1), ("e1", 2), ("e1", 3)])

    def test_new_tick_refires(self):
        rep = FakeReplicator()
        clk = Clock()
        p = pilot(rep, ["e1"], [1, 2], clk)
        p.armed = True
        p.step()
        clk.t += 120.0  # advance one tick
        p.step()
        self.assertEqual(len(rep.fire_calls), 4)  # 2 teams x 2 ticks

    def test_tick_budget_caps_fanout(self):
        rep = FakeReplicator()
        p = pilot(rep, ["e1"], list(range(1, 11)), Clock(), tick_budget=3)
        p.armed = True
        for _ in range(5):
            p.step()
        self.assertEqual(len(rep.fire_calls), 3)  # never exceeds the tick budget

    def test_step_cap_spreads_load(self):
        rep = FakeReplicator()
        p = pilot(rep, ["e1"], list(range(1, 11)), Clock(), max_fires_per_step=2, tick_budget=100)
        p.armed = True
        p.step()
        self.assertEqual(len(rep.fire_calls), 2)  # one step fires at most the cap
        p.step()
        self.assertEqual(len(rep.fire_calls), 4)

    def test_breaker_trips_and_disarms(self):
        rep = FakeReplicator(fire_raises=True)
        p = pilot(rep, ["e1"], list(range(1, 30)), Clock(),
                  breaker_window=4, breaker_error_ratio=0.5, max_fires_per_step=100, tick_budget=100)
        p.armed = True
        p.step()
        self.assertTrue(p.tripped)
        self.assertFalse(p.armed)          # a trip disarms
        # after tripping it fires no more, even across steps
        before = len(rep.fire_calls)
        p.step()
        self.assertEqual(len(rep.fire_calls), before)

    def test_nop_failure_not_retried(self):
        rep = FakeReplicator(nop_ok=False)
        p = pilot(rep, ["e1"], [1], Clock())
        p.armed = True
        p.step()
        p.step()
        self.assertEqual(rep.nop_calls, ["e1"])  # proofed once, remembered as failed


if __name__ == "__main__":
    unittest.main()
