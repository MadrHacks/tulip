"""Flask control-API for the gated Replicator. Arm starts OFF; every fire path
goes through the Replicator's own safety checks. There is no raw-fire endpoint."""

import os

from flask import Flask, jsonify, request

from actuate import Replicator
from config import load_config
from instantiate import target_allowlist

app = Flask(__name__)
cfg = load_config()

_ARMED = os.environ.get("REPLICATOR_ARMED", "").lower() in ("1", "true", "yes")
replicator = Replicator(cfg, armed=_ARMED)


@app.get("/status")
def status():
    return jsonify(armed=replicator.armed, proven=list(replicator.proven))


@app.post("/arm")
def arm():
    replicator.armed = True  # the human gate
    return jsonify(armed=replicator.armed)


@app.post("/disarm")
def disarm():
    replicator.armed = False
    return jsonify(armed=replicator.armed)


@app.post("/nop_proof")
def nop_proof():
    body = request.get_json(force=True) or {}
    try:
        flags = replicator.nop_proof(
            template=body["template"], sploit=body["sploit"],
            service=body["service"], port=body["port"], nop_team=cfg.nop_team,
        )
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(flags=flags)


@app.post("/fanout")
def fanout():
    body = request.get_json(force=True) or {}
    targets = target_allowlist(cfg.team_id, cfg.team_count, cfg.ip_format, cfg.nop_team)
    try:
        results = replicator.fanout(
            template=body["template"], sploit=body["sploit"],
            service=body["service"], port=body["port"], targets=targets,
        )
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(results=results)


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", 8080)))
