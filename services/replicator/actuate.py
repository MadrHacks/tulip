"""Actuation for the replicator: the ONLY place that emits traffic to targets
and hands flags to the farm. Every outbound action is gated by `armed` AND the
anti-leak allowlist (which structurally excludes our own team). Flags go through
the farm, never straight to the gameserver."""

from __future__ import annotations

import json
import re
import socket
import urllib.parse
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


def fetch_flagids(flagids_url: str, service: str, team: int, timeout: float = 5.0) -> list[bytes]:
    """Re-fetch live flagIds for (service, team), always fresh per target so a
    flagId is never carried from one team to another."""
    q = urllib.parse.urlencode({"service": service, "team": team})
    try:
        with urllib.request.urlopen(f"{flagids_url}?{q}", timeout=timeout) as r:
            data = json.load(r)
    except Exception:
        return []
    return [str(v).encode() for v in _leaf_values(data)]


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
