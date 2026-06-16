#!/bin/env python
import os
import re
import time
from datetime import datetime
from pathlib import Path

import psycopg_pool
import requests
import yaml

CONFIG_DIR = os.environ.get("AD_INFRA_CONFIG_DIR", "/config")


def _load(name):
    p = Path(CONFIG_DIR) / f"{name}.yml"
    if p.exists():
        text = p.read_text()
        return yaml.safe_load(text) if text else {}
    return {}


_game = _load("game")

DELAY = 5
tick_length = int(_game.get("tick_duration_sec", 120))
start_date = str(_game.get("start", "") or "")

try:
    team_id = int(_game.get("team_id"))
except (TypeError, ValueError):
    team_id = None

flagid_endpoint = os.getenv("FLAGID_ENDPOINT") or str(_game.get("flag_ids_url", "") or "")
flagid_scrape_enabled = os.getenv("FLAGID_SCRAPE", "") != ""

db = None
if flagid_scrape_enabled:
    print("STARTING FLAGIDS", flush=True)
    print("  TICK_LENGTH:", tick_length, flush=True)
    print("  TICK_START :", start_date, flush=True)
    print("  TEAM_ID    :", team_id, flush=True)
    print("  ENDPOINT   :", flagid_endpoint, flush=True)
    db = psycopg_pool.ConnectionPool(os.environ["TIMESCALE"])
    print("CONNECTED TO TIMESCALE", flush=True)
else:
    print("FLAGID SCRAPE DISABLED", flush=True)


def _leaf_values(node):
    if node is None:
        return
    if isinstance(node, dict):
        for v in node.values():
            yield from _leaf_values(v)
    elif isinstance(node, (list, tuple)):
        for v in node:
            yield from _leaf_values(v)
    else:
        yield node


def _coerce(value):
    if value is None or isinstance(value, bool):
        return None
    s = str(value).strip()
    return s or None


def _team_to_int(raw):
    try:
        return int(raw)
    except (TypeError, ValueError):
        m = re.search(r"(\d+)$", str(raw))
        return int(m.group(1)) if m else None


def _round_to_int(raw):
    try:
        return int(raw)
    except (TypeError, ValueError):
        return -1


def parse_flagids(payload):
    matched_structured = False

    if isinstance(payload, dict):
        for service, teams in payload.items():
            if not isinstance(teams, dict):
                continue
            for raw_team, rounds in teams.items():
                tid = _team_to_int(raw_team)
                if team_id is not None and tid is not None and tid != team_id:
                    continue
                if isinstance(rounds, dict):
                    for raw_round, entry in rounds.items():
                        rnd = _round_to_int(raw_round)
                        for content in _leaf_values(entry):
                            c = _coerce(content)
                            if c is not None:
                                matched_structured = True
                                yield (c, str(service), tid if tid is not None else -1, rnd)
                else:
                    for content in _leaf_values(rounds):
                        c = _coerce(content)
                        if c is not None:
                            matched_structured = True
                            yield (c, str(service), tid if tid is not None else -1, -1)

    if not matched_structured:
        for content in _leaf_values(payload):
            c = _coerce(content)
            if c is not None:
                yield (c, "", -1, -1)


def _request_url():
    url = flagid_endpoint
    if team_id is not None and "team=" not in url:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}team={team_id}"
    return url


def update_flagids():
    assert db is not None

    response = requests.get(_request_url(), timeout=10)
    response.raise_for_status()

    rows = sorted({row for row in parse_flagids(response.json())})
    print("Updating flagids:", time.time(), f"({len(rows)})", flush=True)
    if not rows:
        return

    with db.connection() as conn:
        with conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO flag_id (content, service, team, round)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (content, service, team, round) DO NOTHING
                """,
                rows,
            )
            conn.commit()


def _sleep_until_next_tick():
    if start_date:
        try:
            unixtime = datetime.strptime(start_date, "%Y-%m-%dT%H:%M:%S%z").timestamp()
            into_tick = max(0.0, time.time() - unixtime) % tick_length
            time.sleep((tick_length - into_tick) + DELAY)
            return
        except ValueError:
            pass
    time.sleep(tick_length)


def main():
    while True:
        try:
            if flagid_scrape_enabled:
                update_flagids()
        except Exception as e:
            print("ERROR:", e, flush=True)
            time.sleep(10)
            continue
        _sleep_until_next_tick()


if __name__ == "__main__":
    main()
