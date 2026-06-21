"""Load the replicator Config from the unified config dir (game.yml / farm.yml)."""

from __future__ import annotations

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
    )
