"""Load the replicator Config from the unified config dir (game.yml / farm.yml)."""

from __future__ import annotations

import datetime
import os

import yaml

from actuate import Config


def _load(config_dir: str, name: str) -> dict:
    try:
        with open(os.path.join(config_dir, name)) as f:
            return yaml.safe_load(f) or {}
    except (FileNotFoundError, NotADirectoryError):
        return {}


def load_config(config_dir: str | None = None) -> Config:
    config_dir = config_dir or os.environ.get("AD_INFRA_CONFIG_DIR", "/config")
    game = _load(config_dir, "game.yml")
    farm = _load(config_dir, "farm.yml")
    return Config(
        team_id=int(game.get("team_id", -1)),
        ip_format=game.get("ip_format", "10.60.{}.1"),
        flag_regex=game.get("flag_regex", "[A-Z0-9]{31}="),
        flagids_url=game.get("flag_ids_url", "http://10.10.0.1:8081/flagIds"),
        farm_url=os.environ.get("FARM_URL", "http://farm:5000"),
        farm_token=farm.get("api_token") or farm.get("server_password", ""),
        nop_team=int(game.get("nop_team", 0)),
        team_count=int(game.get("range_ip_teams", 0)),
    )


def load_auto_params(config_dir: str | None = None) -> dict:
    """Game timing for the autonomous loop's tick numbering. tick_start is
    network-open (round 0); consistency matters more than the absolute value."""
    config_dir = config_dir or os.environ.get("AD_INFRA_CONFIG_DIR", "/config")
    game = _load(config_dir, "game.yml")
    tick_duration = float(game.get("tick_duration_sec", 120))
    delay = float(game.get("network_open_delay_min", 0)) * 60
    tick_start = 0.0
    try:
        dt = datetime.datetime.fromisoformat(str(game.get("start", "")).replace("Z", "+00:00"))
        tick_start = dt.timestamp() + delay
    except ValueError:
        pass
    return {"tick_start": tick_start, "tick_duration": tick_duration, "nop_team": int(game.get("nop_team", 0))}
