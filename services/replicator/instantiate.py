"""Side-effect-free core for the replicator service.

Consumes the JSON template that minecore stores and rebuilds request bytes by
filling in per-slot values. NO network, NO firing, NO DB here.

Template shape::

    {
      "segments": [{"const": "<base64 bytes>"} | {"var": true}, ...],
      "slots":    [{"type": "const|flag|flagid|random|unknown",
                    "charclass": "hex|base64|base64url|uuid|jwt|alnum|other",
                    "min_len": int, "max_len": int, "example": "<sample>"}, ...]
    }

The number of ``{"var": true}`` segments equals ``len(slots)``; the i-th var
segment is filled by ``slots[i]``.
"""

from __future__ import annotations

import base64
import secrets
import uuid

_ALPHABETS = {
    "hex": "0123456789abcdef",
    "base64": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    "base64url": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
    "alnum": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
}


def gen_value(slot: dict) -> bytes:
    """Generate a value for ONE slot.

    - random: random string of length in [min_len, max_len] over the charclass
      alphabet (uuid -> a uuid4 string). Falls back to len(example) or 8.
    - const/unknown: the example bytes.
    - flag/flagid: empty (caller supplies these).
    """
    stype = slot.get("type", "unknown")

    if stype in ("flag", "flagid"):
        return b""

    if stype in ("const", "unknown"):
        return (slot.get("example") or "").encode()

    if stype == "random":
        charclass = slot.get("charclass", "alnum")
        if charclass == "uuid":
            return str(uuid.uuid4()).encode()

        example = slot.get("example") or ""
        default_len = len(example) or 8
        min_len = slot.get("min_len")
        max_len = slot.get("max_len")
        if min_len is None:
            min_len = default_len
        if max_len is None:
            max_len = default_len
        if max_len < min_len:
            max_len = min_len
        length = min_len + secrets.randbelow(max_len - min_len + 1)

        alphabet = _ALPHABETS.get(charclass, _ALPHABETS["alnum"])
        return "".join(secrets.choice(alphabet) for _ in range(length)).encode()

    # Unknown type string: treat like const/unknown.
    return (slot.get("example") or "").encode()


def _var_count(template: dict) -> int:
    return sum(1 for seg in template.get("segments", []) if seg.get("var"))


def instantiate(template: dict, slot_values: list[bytes]) -> bytes:
    """Rebuild request bytes from segments + ordered slot_values."""
    segments = template.get("segments", [])
    expected = _var_count(template)
    if len(slot_values) != expected:
        raise ValueError(
            f"slot_values length {len(slot_values)} != var segment count {expected}"
        )

    out = bytearray()
    it = iter(slot_values)
    for seg in segments:
        if seg.get("var"):
            out += next(it)
        else:
            out += base64.b64decode(seg["const"])
    return bytes(out)


def fill_slots(template: dict, *, flagids: list[bytes] | None = None) -> list[bytes]:
    """Produce slot_values for every slot (per-target fill helper).

    A flagid slot pops the next value from ``flagids``; a flag slot stays b"".
    """
    fid_iter = iter(flagids or [])
    values: list[bytes] = []
    for slot in template.get("slots", []):
        if slot.get("type") == "flagid":
            try:
                values.append(next(fid_iter))
            except StopIteration:
                raise ValueError("ran out of flagids while filling slots")
        else:
            values.append(gen_value(slot))
    return values


def is_allowed_target(team_index: int, our_team_id: int) -> bool:
    """Guard: never allow firing at our own team."""
    return team_index != our_team_id


def target_allowlist(
    our_team_id: int, team_count: int, ip_format: str, nop_team: int
) -> list[tuple[int, str]]:
    """Enumerate (team_index, ip) for every team EXCLUDING our own.

    Iterates range(0, team_count + 1) so the NOP team (and any 0-indexed team)
    is included. This is the ONLY place targets are enumerated and it must
    NEVER include our_team_id.
    """
    targets: list[tuple[int, str]] = []
    for team_index in range(0, team_count + 1):
        if not is_allowed_target(team_index, our_team_id):
            continue
        targets.append((team_index, ip_format.format(team_index)))
    return targets
