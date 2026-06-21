"""Flask control-API for the gated Replicator. Arm starts OFF; every fire path
goes through the Replicator's own safety checks. There is no raw-fire endpoint."""

import os
import dataclasses

from flask import Flask, jsonify, request

from actuate import Replicator
from autonomy import AuditLog, Level, Decision
from config import load_config
from instantiate import target_allowlist

app = Flask(__name__)
cfg = load_config()

_ARMED = os.environ.get("REPLICATOR_ARMED", "").lower() in ("1", "true", "yes")
replicator = Replicator(cfg, armed=_ARMED)
audit = AuditLog()


@app.get("/status")
def status():
    return jsonify(armed=replicator.armed, proven=list(replicator.proven))


@app.post("/arm")
def arm():
    replicator.armed = True  # the human gate
    decision = Decision(allow=True, require_human=False, reason="human-initiated")
    audit.record(
        capability="offense",
        action="arm",
        level=Level.AUTO,
        decision=decision,
        subject="",
    )
    return jsonify(armed=replicator.armed)


@app.post("/disarm")
def disarm():
    replicator.armed = False
    decision = Decision(allow=True, require_human=False, reason="human-initiated")
    audit.record(
        capability="offense",
        action="disarm",
        level=Level.MANUAL,
        decision=decision,
        subject="",
    )
    return jsonify(armed=replicator.armed)


@app.post("/nop_proof")
def nop_proof():
    body = request.get_json(force=True) or {}
    sploit = body.get("sploit", "")
    try:
        flags = replicator.nop_proof(
            template=body["template"], sploit=sploit,
            service=body["service"], port=body["port"], nop_team=cfg.nop_team,
        )
        decision = Decision(allow=True, require_human=False, reason="nop verified")
        audit.record(
            capability="offense",
            action="nop_proof",
            level=Level.AUTO,
            decision=decision,
            subject=sploit,
        )
    except ValueError as exc:
        decision = Decision(allow=False, require_human=False, reason=str(exc))
        audit.record(
            capability="offense",
            action="nop_proof",
            level=Level.AUTO,
            decision=decision,
            subject=sploit,
        )
        return jsonify(error=str(exc)), 400
    return jsonify(flags=flags)


@app.post("/fanout")
def fanout():
    body = request.get_json(force=True) or {}
    sploit = body.get("sploit", "")
    targets = target_allowlist(cfg.team_id, cfg.team_count, cfg.ip_format, cfg.nop_team)
    try:
        results = replicator.fanout(
            template=body["template"], sploit=sploit,
            service=body["service"], port=body["port"], targets=targets,
        )
        decision = Decision(allow=True, require_human=False, reason="fanout succeeded")
        audit.record(
            capability="offense",
            action="fanout",
            level=Level.AUTO,
            decision=decision,
            subject=sploit,
        )
    except ValueError as exc:
        decision = Decision(allow=False, require_human=False, reason=str(exc))
        audit.record(
            capability="offense",
            action="fanout",
            level=Level.AUTO,
            decision=decision,
            subject=sploit,
        )
        return jsonify(error=str(exc)), 400
    return jsonify(results=results)


@app.get("/audit")
def get_audit():
    return jsonify(
        [
            dataclasses.asdict(entry)
            for entry in audit.entries()
        ]
    )


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", 8080)))
