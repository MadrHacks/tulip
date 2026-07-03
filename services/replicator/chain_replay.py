"""Multi-flow chain replayer: each step is a fresh request/response to a service
(possibly a different port), with values carried between steps. The stepwise
logic is shared with the interactive replayer via replay_core; only the
transport — one request, one response per step — is defined here.
"""
from __future__ import annotations

from typing import Callable, Optional

from replay_core import run_steps

Send = Callable[[bytes, str, int], bytes]


def replay_chain(plan: dict, send: Send, *, flagids: Optional[list[bytes]] = None) -> dict:
    steps = plan.get("steps", [])
    links = plan.get("links", [])

    def execute(_i: int, step: dict, req: bytes) -> bytes:
        return send(req, step["service"], step["port"])

    return run_steps(steps, links, execute, flagids=flagids)
