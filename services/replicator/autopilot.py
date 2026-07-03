"""Autonomous attack-replication loop with hard anti-DoS rails.

The design keeps runaway impossible by construction:

  * NOP-proof is the precision gate — nothing fans out to a real team until it
    captured a flag at NOP first, so liberal detection is safe.
  * Per-(sploit, team, tick) dedup — each proven exploit is fired at each team AT
    MOST ONCE PER TICK. Flags rotate per tick, so there is never a reason to
    loop; this alone bounds outbound to (#exploits x #teams) per tick.
  * Per-tick budget and per-step cap bound the rate regardless of detection.
  * A circuit breaker disarms the loop on an anomalous error rate.
  * Own-team exclusion is structural (targets come from target_allowlist).
  * AUTO mode is its own explicit arm, off by default and separate from the
    actuator arm.

The loop is transport-free: it is driven by injected callables (candidates
source, targets, clock) and the gated Replicator, so it is fully unit-testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class AutoConfig:
    nop_team: int
    tick_start: float          # unix seconds of round 0
    tick_duration: float       # seconds per tick
    max_fires_per_step: int = 10   # spreads fan-out load across steps
    max_nop_per_step: int = 5      # new NOP proofs attempted per step
    tick_budget: int = 400         # hard cap on fan-out fires per tick
    breaker_window: int = 40       # recent fires considered by the breaker
    breaker_error_ratio: float = 0.5  # trip if this fraction error out


@dataclass
class AutoPilot:
    replicator: object                       # gated Replicator (nop_proof/replicate)
    candidates_fn: Callable[[], list]        # -> [{sploit, template, service, port}]
    targets_fn: Callable[[], list]           # -> [(team_index, ip)], excludes our own
    cfg: AutoConfig
    clock: Callable[[], float]

    armed: bool = False
    proven: dict = field(default_factory=dict)   # sploit -> True/False (nop result)
    _fired: set = field(default_factory=set)     # (sploit, team, tick) already fired
    _tick_fires: dict = field(default_factory=dict)  # tick -> count
    _outcomes: list = field(default_factory=list)    # recent bools for the breaker
    tripped: bool = False

    def current_tick(self) -> int:
        d = self.clock() - self.cfg.tick_start
        return int(d // self.cfg.tick_duration) if self.cfg.tick_duration > 0 else 0

    def _record(self, ok: bool):
        self._outcomes.append(ok)
        if len(self._outcomes) > self.cfg.breaker_window:
            self._outcomes.pop(0)
        if len(self._outcomes) >= self.cfg.breaker_window:
            errs = sum(1 for o in self._outcomes if not o)
            if errs / len(self._outcomes) >= self.cfg.breaker_error_ratio:
                self.tripped = True
                self.armed = False  # a trip disarms; re-arming is a human act

    def step(self) -> dict:
        """One bounded iteration. Returns a summary for observability/tests."""
        if not self.armed or self.tripped:
            return {"armed": self.armed, "tripped": self.tripped, "nop": 0, "fired": 0}

        candidates = self.candidates_fn()
        tick = self.current_tick()

        # 1. NOP-proof new candidates (bounded per step). A candidate never
        # re-proofs; a failure is remembered so we don't hammer NOP with it.
        nop = 0
        for c in candidates:
            if nop >= self.cfg.max_nop_per_step:
                break
            s = c["sploit"]
            if s in self.proven:
                continue
            try:
                self.proven[s] = bool(self._proof(c))
            except Exception:
                self.proven[s] = False
            nop += 1

        # 2. Fan out proven exploits — once per (sploit, team, tick), under the
        # per-step cap and the per-tick budget.
        targets = self.targets_fn()
        fired = 0
        for c in candidates:
            s = c["sploit"]
            if not self.proven.get(s):
                continue
            for team, _ip in targets:
                if self.tripped:  # a breaker trip mid-step halts firing at once
                    return self._summary(tick, nop, fired)
                if fired >= self.cfg.max_fires_per_step:
                    return self._summary(tick, nop, fired)
                if self._tick_fires.get(tick, 0) >= self.cfg.tick_budget:
                    return self._summary(tick, nop, fired)
                key = (s, team, tick)
                if key in self._fired:
                    continue
                # Reserve the slot before firing so the per-tick budget holds
                # even across early returns / dedup, never resetting per step.
                self._fired.add(key)
                self._tick_fires[tick] = self._tick_fires.get(tick, 0) + 1
                fired += 1
                try:
                    self._fire(c, team)
                    self._record(True)
                except Exception:
                    self._record(False)
        return self._summary(tick, nop, fired)

    def _proof(self, c) -> list:
        """NOP-proof a candidate by its kind; returns the captured flags list.
        Single-flow templates return a flags list; interactive/chain replays
        return a dict — normalize both to a list."""
        kind = c.get("kind", "template")
        if kind == "interactive":
            r = self.replicator.nop_proof_session(c["plan"], c["sploit"], self.cfg.nop_team)
        elif kind == "chain":
            r = self.replicator.nop_proof_chain(c["plan"], c["sploit"], self.cfg.nop_team)
        else:
            r = self.replicator.nop_proof(
                template=c["template"], sploit=c["sploit"],
                service=c["service"], port=c["port"], nop_team=self.cfg.nop_team,
            )
        return r.get("flags", []) if isinstance(r, dict) else (r or [])

    def _fire(self, c, team):
        """Fan a proven candidate out to one team, by its kind. The replicator
        re-checks the NOP-proven + allowlist gates on every call."""
        kind = c.get("kind", "template")
        if kind == "interactive":
            return self.replicator.replay_session(c["plan"], c["sploit"], team)
        if kind == "chain":
            return self.replicator.replay(c["plan"], c["sploit"], team)
        return self.replicator.replicate(c["template"], c["sploit"], c["service"], c["port"], team)

    def _summary(self, tick, nop, fired):
        return {
            "armed": self.armed, "tripped": self.tripped, "tick": tick,
            "nop": nop, "fired": fired, "proven": sum(1 for v in self.proven.values() if v),
        }
