"""Interactive (expect-style) replayer for stateful single-connection exploits —
the menu-driven TCP services where one session drives everything: send, read
until a prompt, send, ... until the flag comes back. Single-flow templates can't
express this (it's a conversation, not one request) and chains can't either (it's
one connection, not many), so this is the third replay model.

The connection is injected (a Conn with send / recv_until) to stay pure and
unit-testable; the real socket adapter lives in actuate. The per-step slot,
carry, and link logic is the shared replay_core — only the transport differs:
send the request on the open connection, then read until this step's expect
marker (or whatever is available when expect is absent).
"""
from __future__ import annotations

from typing import Optional, Protocol

from replay_core import run_steps


class Conn(Protocol):
    def send(self, data: bytes) -> None: ...
    def recv_until(self, marker: Optional[bytes]) -> bytes: ...


def replay_interactive(plan: dict, conn: Conn, *, flagids: Optional[list[bytes]] = None,
                       grants: Optional[dict] = None) -> dict:
    # Honor the engine's UNREPRODUCIBLE verdict: a plan gated for a COMPUTED
    # required slot (crypto/session token) or a TLS/WS/opaque service carries no
    # runnable steps and must never be fired — skip it (escalate to a human),
    # never open the connection. Belt-and-suspenders: the candidate reader already
    # filters these out at the DB, but a broken plan must never reach the wire.
    if plan.get("unreproducible"):
        return {
            "ok": False, "steps_run": 0, "responses": [], "carried": {},
            "error": "unreproducible plan: " + (plan.get("reason") or "gated by the reproduction engine"),
        }
    steps = plan.get("steps", [])
    links = plan.get("links", [])

    def execute(_i: int, step: dict, req: bytes) -> bytes:
        conn.send(req)
        marker = step.get("expect")
        if isinstance(marker, str):
            marker = marker.encode()
        return conn.recv_until(marker)

    return run_steps(steps, links, execute, flagids=flagids, grants=grants)
