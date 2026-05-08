#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of Flower.
#
# Copyright ©2018 Nicolò Mazzucato
# Copyright ©2018 Antonio Groza
# Copyright ©2018 Brunello Simone
# Copyright ©2018 Alessio Marotta
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
# Flower is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Flower is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Flower.  If not, see <https://www.gnu.org/licenses/>.

import os
from pathlib import Path

import yaml

CONFIG_DIR = os.environ.get("AD_INFRA_CONFIG_DIR", "/config")


def _load(name):
    p = Path(CONFIG_DIR) / f"{name}.yml"
    if p.exists():
        text = p.read_text()
        return yaml.safe_load(text) if text else {}
    return {}


_game = _load("game")
_vulnbox = _load("vulnbox")
_services = _load("services")

traffic_dir = Path(os.getenv("TULIP_TRAFFIC_DIR", "/traffic"))
dump_pcaps_dir = Path(os.getenv("DUMP_PCAPS", "/traffic"))
tick_length = int(_game.get("tick_duration_sec", 120)) * 1000
flag_lifetime = int(_game.get("flag_lifetime_ticks", 5))
start_date = _game.get("start", "")
flag_regex = _game.get("flag_regex", "[A-Z0-9]{31}=")
vm_ip = _vulnbox.get("ip", "")
visualizer_url = os.getenv("VISUALIZER_URL", "http://127.0.0.1:1337")

vm_ip_1 = vm_ip

services = []
for svc in _services.get("services", []):
    name = svc.get("name", "")
    ports = svc.get("ports", [])
    for port in ports:
        services.append({"ip": vm_ip, "port": port, "name": f"{name}-{port}"})
services += [{"ip": vm_ip_1, "port": -1, "name": "other"}]
