"""Turn a synthesized request template into a human-editable exploit skeleton.

The skeleton emitted by render_scaffold() is a *starting point*: a runnable,
heavily-commented Python script that reproduces the captured request shape and
leaves clearly-marked TODOs where the operator must plug in real logic (re-fetch
the flagId, extract the flag from the response, etc).
"""

import base64

# charclass name -> a python expression string producing one random char,
# evaluated inside the emitted script's body (secrets is imported there).
_CHARCLASS_ALPHABET = {
    "hex": "0123456789abcdef",
    "HEX": "0123456789ABCDEF",
    "digits": "0123456789",
    "alpha": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alnum": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
}


def _decode_const(seg):
    """Return the decoded bytes for a const segment, tolerating bad base64."""
    try:
        return base64.b64decode(seg.get("const", "") or "")
    except Exception:
        return b""


def _slot_len(slot):
    mn = slot.get("min_len")
    mx = slot.get("max_len")
    for v in (mx, mn):
        if isinstance(v, int) and v > 0:
            return v
    return 8


def _example_bytes(slot):
    ex = slot.get("example")
    if isinstance(ex, str):
        return ex.encode("utf-8", "replace")
    if isinstance(ex, (bytes, bytearray)):
        return bytes(ex)
    return b""


def _emit_slot(slot, idx, lines):
    """Append the assignment line(s) for one var segment to `lines`."""
    stype = (slot.get("type") or "unknown").lower()
    name = "slot%d" % idx

    if stype == "flagid":
        lines.append("    # TODO: re-fetch the flagId for this target/round")
        lines.append("    %s = b\"FLAGID\"" % name)

    elif stype == "random":
        n = _slot_len(slot)
        charclass = slot.get("charclass") or "alnum"
        alphabet = _CHARCLASS_ALPHABET.get(charclass, _CHARCLASS_ALPHABET["alnum"])
        lines.append("    # random %s value, length %d (charclass=%s)"
                     % (charclass, n, charclass))
        lines.append("    %s = bytes(secrets.choice(%r.encode()) for _ in range(%d))"
                     % (name, alphabet, n))

    elif stype == "const":
        lines.append("    # constant captured from the original request")
        lines.append("    %s = %r" % (name, _example_bytes(slot)))

    else:  # flag, unknown, or anything unexpected
        lines.append("    # TODO: figure out what goes here (slot type=%s)" % stype)
        lines.append("    %s = b\"...\"" % name)


def render_scaffold(template: dict, service: str = "service",
                    host: str = "TARGET", port: int = 0) -> str:
    template = template or {}
    segments = template.get("segments") or []
    slots = template.get("slots") or []

    lines = []
    lines.append("#!/usr/bin/env python3")
    lines.append("# Exploit skeleton for service %r." % service)
    lines.append("# Auto-generated starting point -- edit freely before use.")
    lines.append("import socket")
    lines.append("import secrets")
    lines.append("")
    lines.append("HOST = %r" % host)
    lines.append("PORT = %d" % int(port))
    lines.append("")
    lines.append("def exploit(host=HOST, port=PORT):")
    lines.append("    # --- build the per-slot values ---")

    # Walk segments; the i-th {"var": True} segment maps to slots[i].
    var_idx = 0
    request_parts = []  # python expressions to concatenate, in segment order
    for seg in segments:
        if isinstance(seg, dict) and seg.get("var"):
            slot = slots[var_idx] if var_idx < len(slots) else {}
            _emit_slot(slot, var_idx, lines)
            request_parts.append("slot%d" % var_idx)
            var_idx += 1
        else:
            decoded = _decode_const(seg) if isinstance(seg, dict) else b""
            request_parts.append(repr(decoded))

    lines.append("")
    lines.append("    # --- assemble the request bytes (segment order) ---")
    if request_parts:
        lines.append("    request = b\"\".join([")
        for part in request_parts:
            lines.append("        %s," % part)
        lines.append("    ])")
    else:
        lines.append("    request = b\"\"")

    lines.append("")
    lines.append("    # --- send it and read the response ---")
    lines.append("    sock = socket.create_connection((host, port), timeout=5)")
    lines.append("    try:")
    lines.append("        sock.sendall(request)")
    lines.append("        sock.shutdown(socket.SHUT_WR)")
    lines.append("        chunks = []")
    lines.append("        while True:")
    lines.append("            data = sock.recv(4096)")
    lines.append("            if not data:")
    lines.append("                break")
    lines.append("            chunks.append(data)")
    lines.append("    finally:")
    lines.append("        sock.close()")
    lines.append("    response = b\"\".join(chunks)")
    lines.append("")
    lines.append("    # TODO: extract the flag from `response` and submit it")
    lines.append("    print(response)")
    lines.append("    return response")
    lines.append("")
    lines.append("")
    lines.append("if __name__ == \"__main__\":")
    lines.append("    exploit()")
    lines.append("")

    return "\n".join(lines)
