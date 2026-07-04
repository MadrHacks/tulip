"""Shared stepwise-replay driver for both multi-flow chains and single-connection
interactive sessions. The only thing that differs between them is the transport
for one step (a fresh request/response vs. a send + read-until on a persistent
connection), so that is injected as ``execute`` and everything else — slot
filling, carried-value inject/extract, link wiring — lives here once.

This is the REPLAY EXECUTION for the interactive plans the Go reproduction
engine emits (reprosynth.go, ported from the validated reference engine). It
resolves the reference's typed slots against a LIVE service, per turn:

  * FLAGID  — the live flagId for this target/tick (granted via ``flagids``).
  * RANDOM  — a fresh nonce, generated once (fill_slots) and reused consistently
              downstream via SELFREF links (register creds reused at login).
  * SELFREF — copy an earlier step's own SENT slot value (its ``producer_slot``).
  * MIRROR  — extract a value from an EARLIER SERVER response (the producer
              step's response) between the link's delimiters, then apply the
              named transform (identity/base64/hex/url). DERIVED live, never
              granted — this is the real fidelity test.
  * LENGTH  — a Content-Length: RECOMPUTED over the assembled body bytes (never
              granted; a fresh-length body needs a fresh length).
  * CONST   — copied literally (the template's const segments).
  * COMPUTED — unreproducible (crypto/HMAC/session token). Never fired: a step
              carrying one gates the whole plan, fail-closed.

The engine stays conservative: anything it cannot mechanically reconstruct fails
the plan rather than firing broken bytes at a target.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Callable, Optional
from urllib.parse import quote_from_bytes

from instantiate import fill_slots, instantiate

# execute(step_index, step, request_bytes) -> response_bytes
Execute = Callable[[int, dict, bytes], bytes]


def compile_pattern(pattern) -> "re.Pattern[bytes]":
    if isinstance(pattern, str):
        pattern = pattern.encode()
    return re.compile(pattern)


# ---------------------------------------------------------------- mirror transforms
# from_server(x): reconstruct the CLIENT value from the server representation x
# captured between a mirror link's delimiters. Ported verbatim from the reference
# engine's TRANSFORMS (from_server column). identity is the genuine aviation exfil
# path; the rest cover base64/hex/url-wrapped mirrors. A decode failure returns
# None so the plan fails closed rather than firing malformed bytes.


def _from_identity(x: bytes) -> Optional[bytes]:
    return x


def _from_b64decode(x: bytes) -> Optional[bytes]:
    # client value is base64 whose DECODE appears in the server -> re-encode.
    return base64.b64encode(x)


def _from_b64encode(x: bytes) -> Optional[bytes]:
    # server carries base64; client uses the DECODED bytes.
    try:
        return base64.b64decode(x + b"==")
    except Exception:
        return None


def _from_hexdecode(x: bytes) -> Optional[bytes]:
    # client value is hex whose DECODE appears in the server -> re-hexlify.
    return binascii.hexlify(x)


def _from_hexencode(x: bytes) -> Optional[bytes]:
    # server carries hex; client uses the DECODED bytes.
    try:
        return binascii.unhexlify(x)
    except Exception:
        return None


def _from_urldecode(x: bytes) -> Optional[bytes]:
    # server carries the raw bytes; client percent-encodes them.
    return quote_from_bytes(x, safe=b"").encode()


_MIRROR_FROM_SERVER = {
    "": _from_identity,          # legacy links with no transform
    "identity": _from_identity,
    "b64decode": _from_b64decode,
    "b64encode": _from_b64encode,
    "hexdecode": _from_hexdecode,
    "hexencode": _from_hexencode,
    "urldecode": _from_urldecode,
}


def apply_mirror_transform(name: Optional[str], rep: bytes) -> Optional[bytes]:
    """Reconstruct the client value from a captured server representation, per the
    link's transform. Returns None on an unknown transform or a decode failure."""
    fn = _MIRROR_FROM_SERVER.get(name or "identity")
    if fn is None:
        return None
    try:
        return fn(rep)
    except Exception:
        return None


def _body_bytes(request: bytes) -> bytes:
    """The HTTP body: everything after the header/body separator (empty for a
    line-protocol request with no separator). Matches the reference's derivation
    of a Content-Length source."""
    sep = request.find(b"\r\n\r\n")
    return request[sep + 4:] if sep >= 0 else b""


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


def run_steps(steps: list[dict], links: list[dict], execute: Execute, *, flagids=None,
              grants=None) -> dict:
    """Drive an ordered list of steps, carrying derived values between them.

    Two link kinds (from the reproduction engine):

      * "mirror" (default, incl. legacy links with no ``kind``): extract a value
        from a producer step's RESPONSE (Extract's capture group 1), apply the
        link's ``transform`` (identity/base64/hex/url), and inject it into a later
        step's slot — e.g. a session Bearer token echoed at login.
      * "selfref": copy a producer step's own SENT slot value (its
        ``producer_slot``) into a later step's slot — e.g. register credentials
        reused verbatim at login.

    For each step: fill its slots, inject any carried/self-referenced values a
    link routes into it, RECOMPUTE any LENGTH (Content-Length) slots over the
    assembled body, build the request, run the injected transport, then extract
    (and transform) any values later mirror links consume.

    A COMPUTED slot (crypto/session token the engine could not prove regenerable)
    in a step fails the plan closed: it is unreproducible and must never be fired.

    ``grants`` is a held-out-fidelity affordance (default None -> no effect, the
    production path never passes it): ``{step_index: {slot_index: bytes}}`` of
    pre-supplied slot values applied right after fill_slots. It exists so the
    leave-one-out fidelity test can GRANT the "fresh flagId + fresh nonces" (the
    held-out instance's OWN unpredictable RANDOM/flagId values) exactly as the
    reference engine does, while MIRROR/SELFREF/LENGTH stay DERIVED (never granted)
    — the real test of the model.
    """
    producers, consumers = _wire(links)
    responses: list[bytes] = []
    carried: dict[int, bytes] = {}
    sent_slots: dict[int, list[bytes]] = {}

    for i, step in enumerate(steps):
        template = step["template"]
        tslots = template.get("slots", [])

        # A COMPUTED slot is unreproducible: refuse to build the request from it
        # rather than fire malformed bytes (the Go engine already gates such plans
        # as Unreproducible; this is the fail-closed backstop at execution).
        for si, slot in enumerate(tslots):
            if slot.get("type") == "computed":
                return _fail(
                    i, responses, carried,
                    f"step {i} slot {si}: COMPUTED (unreproducible) — refusing to fire",
                )

        slot_values = fill_slots(template, flagids=flagids)

        # Held-out fidelity grants: substitute the held-out instance's OWN
        # RANDOM/flagId values (unpredictable, hence granted just like the
        # reference) BEFORE link injection and length recompute, so SELFREF
        # producers carry the granted value and LENGTH still recomputes over it.
        if grants:
            for si_slot, val in grants.get(i, {}).items():
                slot_values[si_slot] = val

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

        # LENGTH: recompute Content-Length AFTER every other slot (incl. the
        # link-injected mirror/selfref values) is known, so a fresh-length body
        # gets a correct length. Derived, never granted.
        len_slots = [si for si, slot in enumerate(tslots) if slot.get("type") == "length"]
        if len_slots:
            for si in len_slots:
                slot_values[si] = b""
            body = _body_bytes(instantiate(template, slot_values))
            length = str(len(body)).encode()
            for si in len_slots:
                slot_values[si] = length

        sent_slots[i] = slot_values
        req = instantiate(template, slot_values)
        resp = execute(i, step, req)
        responses.append(resp)

        for li in producers.get(i, ()):
            link = links[li]
            if link.get("kind") == "selfref":
                continue  # selfref producers carry no response extract
            m = compile_pattern(link["extract"]).search(resp)
            if m is None:
                return _fail(
                    i + 1, responses, carried,
                    f"link {li}: extract regex did not match response of producer step {i}",
                )
            value = apply_mirror_transform(link.get("transform"), m.group(1))
            if value is None:
                return _fail(
                    i + 1, responses, carried,
                    f"link {li}: mirror transform {link.get('transform')!r} failed to "
                    f"decode the captured value from producer step {i}",
                )
            carried[li] = value

    return {"ok": True, "steps_run": len(steps), "responses": responses, "carried": carried, "error": None}
