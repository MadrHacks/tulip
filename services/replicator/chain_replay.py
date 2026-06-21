"""Session state-machine replayer for multi-step A/D exploit chains.

A ChainPlan is an ordered list of single-flow steps plus links that carry a
value extracted from one step's response into a later step's request. The
transport is injected (Callable[[bytes, str, int], bytes]) to keep this pure
and unit-testable; the real socket/TLS adapter lives elsewhere.
"""
from __future__ import annotations

import re
from typing import Callable, Optional

from instantiate import fill_slots, instantiate

Send = Callable[[bytes, str, int], bytes]


def _compile(pattern) -> "re.Pattern[bytes]":
    if isinstance(pattern, str):
        pattern = pattern.encode()
    return re.compile(pattern)


def replay_chain(plan: dict, send: Send, *, flagids: Optional[list[bytes]] = None) -> dict:
    steps = plan.get("steps", [])
    links = plan.get("links", [])

    producers: dict[int, list[int]] = {}
    consumers: dict[int, list[int]] = {}
    for li, link in enumerate(links):
        producers.setdefault(link["producer_step"], []).append(li)
        consumers.setdefault(link["consumer_step"], []).append(li)
    for d in (producers, consumers):
        for k in d:
            d[k].sort()

    responses: list[bytes] = []
    carried: dict[int, bytes] = {}

    for i, step in enumerate(steps):
        slot_values = fill_slots(step["template"], flagids=flagids)

        for li in consumers.get(i, ()):
            if li not in carried:
                return {
                    "ok": False,
                    "steps_run": i,
                    "responses": responses,
                    "carried": carried,
                    "error": (
                        f"link {li}: missing carried value for consumer step {i} "
                        f"(producer step {links[li]['producer_step']} extract failed)"
                    ),
                }
            slot_values[links[li]["inject_slot"]] = carried[li]

        req = instantiate(step["template"], slot_values)
        resp = send(req, step["service"], step["port"])
        responses.append(resp)

        for li in producers.get(i, ()):
            m = _compile(links[li]["extract"]).search(resp)
            if m is None:
                return {
                    "ok": False,
                    "steps_run": i + 1,
                    "responses": responses,
                    "carried": carried,
                    "error": f"link {li}: extract regex did not match response of producer step {i}",
                }
            carried[li] = m.group(1)

    return {
        "ok": True,
        "steps_run": len(steps),
        "responses": responses,
        "carried": carried,
        "error": None,
    }
