"""Actuation for the replicator: the ONLY place that emits traffic to targets
and hands flags to the farm. Every outbound action is gated by `armed` AND the
anti-leak allowlist (which structurally excludes our own team). Flags go through
the farm, never straight to the gameserver."""

from __future__ import annotations

import json
import re
import socket
import urllib.request
from dataclasses import dataclass

from chain_replay import replay_chain
from interactive_replay import replay_interactive
from instantiate import fill_slots, instantiate, is_allowed_target


@dataclass
class Config:
    team_id: int
    ip_format: str
    flag_regex: str
    flagids_url: str
    farm_url: str
    farm_token: str
    nop_team: int = 0
    team_count: int = 0


def extract_flags(data: bytes, flag_regex: str) -> list[str]:
    return re.findall(flag_regex, data.decode("latin-1"))


def fire_once(ip: str, port: int, request: bytes, timeout: float = 5.0) -> bytes:
    with socket.create_connection((ip, port), timeout=timeout) as s:
        s.sendall(request)
        s.settimeout(timeout)
        chunks = []
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except socket.timeout:
            pass
    return b"".join(chunks)


class SocketConn:
    """Persistent-connection adapter for interactive replay: send bytes, then
    read until a marker appears (or the stream idles / EOFs). The socket is
    injected so the buffering is unit-testable; use connect() for a real one."""

    def __init__(self, sock, timeout: float = 5.0):
        self.sock = sock
        self.timeout = timeout
        self.buf = b""

    @classmethod
    def connect(cls, ip: str, port: int, timeout: float = 5.0) -> "SocketConn":
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        return cls(sock, timeout)

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def recv_until(self, marker) -> bytes:
        while marker is None or marker not in self.buf:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            self.buf += chunk
        if marker is not None:
            idx = self.buf.find(marker)
            if idx >= 0:
                end = idx + len(marker)
                out, self.buf = self.buf[:end], self.buf[end:]
                return out
        out, self.buf = self.buf, b""
        return out

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass


def _leaf_values(node):
    if isinstance(node, dict):
        for v in node.values():
            yield from _leaf_values(v)
    elif isinstance(node, list):
        for v in node:
            yield from _leaf_values(v)
    elif node is not None:
        yield node


def _norm_service(name) -> str:
    """Normalize a service / flagstore name for matching: lowercase and drop a
    trailing '-<n>' flagstore ordinal, so the lowercase mine service name
    ('skypedia') resolves to the gameserver's flagstore shortnames
    ('Skypedia-1', 'Skypedia-2') — one docker service, several flagstores."""
    return re.sub(r"-\d+$", "", str(name).strip()).lower()


def _team_key_matches(feed_team, team: int) -> bool:
    """Whether a feed team key denotes `team`. Accepts a bare id ('7'), a dotted
    team IP ('10.60.7.1' -> 3rd octet, per ip_format 10.60.{}.1), or a key whose
    single integer is the id. Exact-id match is preferred to avoid colliding with a
    round number when the feed collapsed its team level."""
    s = str(feed_team).strip()
    if s == str(team):
        return True
    nums = re.findall(r"\d+", s)
    if len(nums) == 4:  # dotted IPv4: the team is the 3rd octet
        return nums[2] == str(team)
    return len(nums) == 1 and nums[0] == str(team)


def _looks_team_keyed(keys) -> bool:
    ks = [str(k) for k in keys]
    return bool(ks) and all(re.fullmatch(r"[\d.]+", k) for k in ks)


def _flagids_for_team(subtree, team: int) -> list[bytes]:
    """Flatten flagId values for `team` from a team-keyed flagstore subtree
    ``{ "<team>": { "<round>": {...} } }``. A team with no live flag yields
    nothing (we fetch the full, unambiguously nested feed, so a missing team key
    is a real absence, not a server-collapsed level). A non-dict subtree — already
    reduced to a list/scalar of ids — is flattened as-is."""
    if isinstance(subtree, dict):
        teamed = [v for k, v in subtree.items() if _team_key_matches(k, team)]
        return [str(v).encode() for node in teamed for v in _leaf_values(node)]
    return [str(v).encode() for v in _leaf_values(subtree)]


def select_flagids(data, service: str, team: int) -> list[bytes]:
    """Pull the flagId values for (service, team) out of a gameserver feed.

    CC2026 feed shape: ``{ "<flagstore>": { "<team>": { "<round>": {"<desc>":
    "<value>"} } } }`` (optionally wrapped under a top-level "services" key). The
    flagstore key is the capitalized service name plus a flagstore ordinal
    (``Skypedia-1``), while our mine service name is the lowercase docker service
    (``skypedia``): match by normalized name so ONE mine service resolves to ALL
    its flagstores. When no top-level key matches by name AND the top level is
    team-keyed, the feed was already service-filtered -> narrow by team. When the
    top level is OTHER service names (ours absent), return nothing rather than
    inject a foreign service's flagIds."""
    if isinstance(data, dict) and isinstance(data.get("services"), dict):
        data = data["services"]
    if not isinstance(data, dict):
        return [str(v).encode() for v in _leaf_values(data)]

    matched = [sub for key, sub in data.items()
               if _norm_service(key) == _norm_service(service)]
    if matched:
        out: list[bytes] = []
        for sub in matched:
            out.extend(_flagids_for_team(sub, team))
        return out

    if _looks_team_keyed(data.keys()):
        return _flagids_for_team(data, team)
    return []


def fetch_flagids(flagids_url: str, service: str, team: int, timeout: float = 5.0) -> list[bytes]:
    """Re-fetch live flagIds for (service, team), always fresh per target so a
    flagId is never carried from one team to another.

    Both service AND team are resolved CLIENT-SIDE from the full feed (see
    select_flagids): the feed's top-level key is a flagstore shortname
    (``Skypedia-1``) that a lowercase ``?service=skypedia`` query would never match,
    so a strict server-side service filter would silently return zero ids — the
    exact bug that made live substitution ship stale/blank flagIds. Fetching the
    full feed (no filters) also keeps the ``{service:{team:{round}}}`` nesting
    unambiguous, so a missing team key is a true absence rather than a
    server-collapsed level."""
    try:
        with urllib.request.urlopen(flagids_url, timeout=timeout) as r:
            data = json.load(r)
    except Exception:
        return []
    return select_flagids(data, service, team)


def submit_to_farm(cfg: Config, flags: list[str], sploit: str, team: int, timeout: float = 5.0) -> None:
    if not flags:
        return
    body = json.dumps([{"flag": f, "sploit": sploit, "team": str(team)} for f in flags]).encode()
    req = urllib.request.Request(
        f"{cfg.farm_url}/api/post_flags",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": cfg.farm_token},
    )
    try:
        urllib.request.urlopen(req, timeout=timeout)
    except Exception:
        pass


class Replicator:
    """Fires templates at targets. Nothing leaves this object unless `armed` is
    True, and never at our own team."""

    def __init__(self, cfg: Config, armed: bool = False):
        self.cfg = cfg
        self.armed = armed
        self.proven: set[str] = set()  # sploits that captured a flag against NOP

    def replicate(self, template: dict, sploit: str, service: str, port: int, team: int) -> list[str]:
        if not is_allowed_target(team, self.cfg.team_id):
            raise ValueError(f"refusing to target our own team {team}")
        if not self.armed:
            return []
        flagids = fetch_flagids(self.cfg.flagids_url, service, team)
        request = instantiate(template, fill_slots(template, flagids=flagids))
        response = fire_once(self.cfg.ip_format.format(team), port, request)
        flags = extract_flags(response, self.cfg.flag_regex)
        submit_to_farm(self.cfg, flags, sploit, team)
        return flags

    def nop_proof(self, template: dict, sploit: str, service: str, port: int, nop_team: int) -> list[str]:
        """Fire at NOP first; a sploit that captures a flag here is marked proven
        and only then becomes eligible for fan-out."""
        flags = self.replicate(template, sploit, service, port, nop_team)
        if flags:
            self.proven.add(sploit)
        return flags

    def fanout(self, template: dict, sploit: str, service: str, port: int,
               targets: list[tuple[int, str]]) -> dict[int, list[str]]:
        """Fire a NOP-proven sploit at each target. Refuses any sploit that has
        not been proven against NOP."""
        if sploit not in self.proven:
            raise ValueError(f"{sploit} not NOP-proven; refusing fan-out")
        return {team: self.replicate(template, sploit, service, port, team) for team, _ in targets}

    def replay(self, plan: dict, sploit: str, team: int) -> dict:
        """Replay a multi-step chain plan against one target, carrying values
        between steps. Gated exactly like replicate (armed + allowlist, never our
        own team); flags found in any step response go to the farm. Returns a
        JSON-safe summary, not raw response bytes."""
        if not is_allowed_target(team, self.cfg.team_id):
            raise ValueError(f"refusing to target our own team {team}")
        steps = plan.get("steps", [])
        if not steps:
            raise ValueError("empty chain plan")
        if not self.armed:
            return {"ok": False, "armed": False, "flags": []}

        ip = self.cfg.ip_format.format(team)
        flagids = fetch_flagids(self.cfg.flagids_url, steps[0].get("service", ""), team)

        def send(request: bytes, service: str, port: int) -> bytes:
            return fire_once(ip, port, request)

        result = replay_chain(plan, send, flagids=flagids)
        flags: list[str] = []
        for response in result["responses"]:
            flags.extend(extract_flags(response, self.cfg.flag_regex))
        submit_to_farm(self.cfg, flags, sploit, team)
        return {
            "ok": result["ok"],
            "steps_run": result["steps_run"],
            "error": result["error"],
            "flags": flags,
        }

    def nop_proof_chain(self, plan: dict, sploit: str, nop_team: int) -> dict:
        """Replay a chain at NOP first; a chain that captures a flag here is
        marked proven and only then becomes eligible for fan-out."""
        result = self.replay(plan, sploit, nop_team)
        if result["flags"]:
            self.proven.add(sploit)
        return result

    def fanout_chain(self, plan: dict, sploit: str,
                     targets: list[tuple[int, str]]) -> dict[int, dict]:
        """Replay a NOP-proven chain at each target. Refuses any chain that has
        not been proven against NOP."""
        if sploit not in self.proven:
            raise ValueError(f"{sploit} not NOP-proven; refusing fan-out")
        return {team: self.replay(plan, sploit, team) for team, _ in targets}

    def replay_session(self, plan: dict, sploit: str, team: int) -> dict:
        """Replay a stateful interactive session against one target over a single
        connection (send / read-until-prompt / send ...). Gated exactly like
        replicate (armed + allowlist, never our own team); flags in any turn's
        response go to the farm. Returns a JSON-safe summary, not raw bytes."""
        if not is_allowed_target(team, self.cfg.team_id):
            raise ValueError(f"refusing to target our own team {team}")
        steps = plan.get("steps", [])
        if not steps:
            raise ValueError("empty interactive plan")
        if not self.armed:
            return {"ok": False, "armed": False, "flags": []}

        ip = self.cfg.ip_format.format(team)
        port = plan.get("port") or steps[0].get("port")
        flagids = fetch_flagids(self.cfg.flagids_url, plan.get("service", ""), team)

        conn = SocketConn.connect(ip, port)
        try:
            result = replay_interactive(plan, conn, flagids=flagids)
        finally:
            conn.close()

        flags: list[str] = []
        for response in result["responses"]:
            flags.extend(extract_flags(response, self.cfg.flag_regex))
        submit_to_farm(self.cfg, flags, sploit, team)
        return {
            "ok": result["ok"],
            "steps_run": result["steps_run"],
            "error": result["error"],
            "flags": flags,
        }

    def nop_proof_session(self, plan: dict, sploit: str, nop_team: int) -> dict:
        """Replay an interactive session at NOP first; one that captures a flag
        here is marked proven and only then becomes eligible for fan-out."""
        result = self.replay_session(plan, sploit, nop_team)
        if result["flags"]:
            self.proven.add(sploit)
        return result

    def fanout_session(self, plan: dict, sploit: str,
                       targets: list[tuple[int, str]]) -> dict[int, dict]:
        """Replay a NOP-proven interactive session at each target. Refuses any
        session that has not been proven against NOP."""
        if sploit not in self.proven:
            raise ValueError(f"{sploit} not NOP-proven; refusing fan-out")
        return {team: self.replay_session(plan, sploit, team) for team, _ in targets}
