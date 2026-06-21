"""Centralized autonomy choke point + append-only audit trail for the A/D system.

Every side-effecting decision (arm, fire-at-NOP, fan-out, deploy-rule, enable-rule)
from either actuator (offense/replicator, defense/patch-engine) routes through
authority() before acting, and is recorded in an AuditLog the operator can review.
"""
import enum
import time
import dataclasses


class Level(enum.Enum):
    MANUAL = "manual"
    ASSIST = "assist"
    AUTO = "auto"


@dataclasses.dataclass(frozen=True)
class Decision:
    allow: bool
    require_human: bool
    reason: str


def authority(
    capability: str,
    action: str,
    level: Level,
    invariants_ok: bool,
    kill_switch: bool = False,
) -> Decision:
    """Conservative gate. allow is True ONLY when level==AUTO and invariants_ok
    and not kill_switch."""
    if kill_switch:
        return Decision(False, False, "kill-switch engaged")
    if not invariants_ok:
        return Decision(False, False, "invariant failed: " + action)
    if level is Level.MANUAL:
        return Decision(False, True, "manual: human must act")
    if level is Level.ASSIST:
        return Decision(False, True, "assist: proposed, awaiting human")
    # level is AUTO, invariants hold, no kill-switch
    return Decision(True, False, "auto: invariants hold")


@dataclasses.dataclass(frozen=True)
class AuditEntry:
    ts: float
    capability: str
    action: str
    level: str
    allowed: bool
    require_human: bool
    reason: str
    subject: str


class AuditLog:
    """Append-only log of decisions. Nothing is ever deleted or edited."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def record(
        self,
        capability: str,
        action: str,
        level: Level,
        decision: Decision,
        subject: str = "",
    ) -> AuditEntry:
        entry = AuditEntry(
            ts=time.time(),
            capability=capability,
            action=action,
            level=level.value,
            allowed=decision.allow,
            require_human=decision.require_human,
            reason=decision.reason,
            subject=subject,
        )
        self._entries.append(entry)
        return entry

    def entries(self) -> tuple[AuditEntry, ...]:
        """Immutable snapshot; callers cannot mutate the internal list."""
        return tuple(self._entries)


def gate(
    log: AuditLog,
    capability: str,
    action: str,
    level: Level,
    invariants_ok: bool,
    *,
    kill_switch: bool = False,
    subject: str = "",
) -> Decision:
    """Evaluate authority(), record it, and return the Decision."""
    decision = authority(capability, action, level, invariants_ok, kill_switch)
    log.record(capability, action, level, decision, subject)
    return decision
