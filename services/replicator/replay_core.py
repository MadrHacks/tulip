"""Shared stepwise-replay driver for both multi-flow chains and single-connection
interactive sessions. The only thing that differs between them is the transport
for one step (a fresh request/response vs. a send + read-until on a persistent
connection), so that is injected as ``execute`` and everything else — slot
filling, carried-value inject/extract, link wiring — lives here once.
"""

from __future__ import annotations

import re
from typing import Callable

from instantiate import fill_slots, instantiate

# execute(step_index, step, request_bytes) -> response_bytes
Execute = Callable[[int, dict, bytes], bytes]


def compile_pattern(pattern) -> "re.Pattern[bytes]":
    if isinstance(pattern, str):
        pattern = pattern.encode()
    return re.compile(pattern)


def _wire(links: list[dict]) -> tuple[dict, dict]:
    producers: dict[int, list[int]] = {}
    consumers: dict[int, list[int]] = {}
    for li, link in enumerate(links):
        producers.setdefault(link["producer_step"], []).append(li)
        consumers.setdefault(link["consumer_step"], []).append(li)
    for d in (producers, consumers):
        for k in d:
            d[k].sort()
    return producers, consumers


def _fail(steps_run, responses, carried, error) -> dict:
    return {"ok": False, "steps_run": steps_run, "responses": responses, "carried": carried, "error": error}


def run_steps(steps: list[dict], links: list[dict], execute: Execute, *, flagids=None) -> dict:
    """Drive an ordered list of steps, carrying derived values between them.

    Two link kinds (from the reproduction engine):

      * "mirror" (default, incl. legacy links with no ``kind``): extract a value
        from a producer step's RESPONSE (Extract's capture group 1) and inject it
        into a later step's slot — e.g. a session Bearer token echoed at login.
      * "selfref": copy a producer step's own SENT slot value (its
        ``producer_slot``) into a later step's slot — e.g. register credentials
        reused verbatim at login.

    For each step: fill its slots, inject any carried/self-referenced values a
    link routes into it, build the request, run the injected transport, then
    extract any values later mirror links consume.
    """
    producers, consumers = _wire(links)
    responses: list[bytes] = []
    carried: dict[int, bytes] = {}
    sent_slots: dict[int, list[bytes]] = {}

    for i, step in enumerate(steps):
        slot_values = fill_slots(step["template"], flagids=flagids)

        for li in consumers.get(i, ()):
            link = links[li]
            if link.get("kind") == "selfref":
                src = sent_slots.get(link["producer_step"])
                ps = link.get("producer_slot", 0)
                if src is None or ps >= len(src):
                    return _fail(
                        i, responses, carried,
                        f"link {li}: selfref source slot {ps} of step "
                        f"{link['producer_step']} unavailable for consumer step {i}",
                    )
                slot_values[link["inject_slot"]] = src[ps]
                continue
            if li not in carried:
                return _fail(
                    i, responses, carried,
                    f"link {li}: missing carried value for consumer step {i} "
                    f"(producer step {link['producer_step']} extract failed)",
                )
            slot_values[link["inject_slot"]] = carried[li]

        sent_slots[i] = slot_values
        req = instantiate(step["template"], slot_values)
        resp = execute(i, step, req)
        responses.append(resp)

        for li in producers.get(i, ()):
            if links[li].get("kind") == "selfref":
                continue  # selfref producers carry no response extract
            m = compile_pattern(links[li]["extract"]).search(resp)
            if m is None:
                return _fail(
                    i + 1, responses, carried,
                    f"link {li}: extract regex did not match response of producer step {i}",
                )
            carried[li] = m.group(1)

    return {"ok": True, "steps_run": len(steps), "responses": responses, "carried": carried, "error": None}
