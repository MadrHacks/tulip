"""Flask control-API for the gated PatchEngine. Arm starts OFF; rule activation
goes through the engine's own safety checks (synthesis refuses SLA-killing rules,
rules are created inactive, enabling requires armed)."""

import os
import dataclasses

from flask import Flask, jsonify, request

from autonomy import AuditLog, Level, Decision
from deploy import PatchEngine
from firegex_client import FiregexClient

app = Flask(__name__)

firegex = FiregexClient(
    base_url=os.environ.get("FIREGEX_URL", "http://localhost:4444"),
    password=os.environ.get("FIREGEX_PASSWORD", ""),
)

_ARMED = os.environ.get("PATCH_ENGINE_ARMED", "").lower() in ("1", "true", "yes")
engine = PatchEngine(firegex, armed=_ARMED)
audit = AuditLog()


@app.get("/status")
def status():
    return jsonify(armed=engine.armed)


@app.post("/arm")
def arm():
    engine.armed = True  # the human gate
    decision = Decision(allow=True, require_human=False, reason="human-initiated")
    audit.record(
        capability="defense",
        action="arm",
        level=Level.AUTO,
        decision=decision,
        subject="",
    )
    return jsonify(armed=engine.armed)


@app.post("/disarm")
def disarm():
    engine.armed = False
    decision = Decision(allow=True, require_human=False, reason="human-initiated")
    audit.record(
        capability="defense",
        action="disarm",
        level=Level.MANUAL,
        decision=decision,
        subject="",
    )
    return jsonify(armed=engine.armed)


@app.post("/propose")
def propose():
    body = request.get_json(force=True) or {}
    cluster_tag = body.get("cluster_tag", "")
    regex_id = engine.propose(
        cluster_tag=cluster_tag, const_tokens=body["const_tokens"],
        benign_samples=body["benign_samples"], service_id=body["service_id"],
        mode=body.get("mode", "B"),
    )
    decision = Decision(
        allow=regex_id is not None,
        require_human=False,
        reason="propose completed" if regex_id is not None else "propose failed",
    )
    audit.record(
        capability="defense",
        action="propose",
        level=Level.AUTO,
        decision=decision,
        subject=cluster_tag,
    )
    return jsonify(regex_id=regex_id)


@app.post("/arm_rule")
def arm_rule():
    body = request.get_json(force=True) or {}
    cluster_tag = body.get("cluster_tag", "")
    result = engine.arm_rule(cluster_tag=cluster_tag)
    decision = Decision(allow=True, require_human=False, reason="rule armed")
    audit.record(
        capability="defense",
        action="arm_rule",
        level=Level.AUTO,
        decision=decision,
        subject=cluster_tag,
    )
    return jsonify(result=result)


@app.post("/rollback")
def rollback():
    body = request.get_json(force=True) or {}
    cluster_tag = body.get("cluster_tag", "")
    result = engine.rollback(cluster_tag=cluster_tag)
    decision = Decision(allow=True, require_human=False, reason="rollback initiated")
    audit.record(
        capability="defense",
        action="rollback",
        level=Level.AUTO,
        decision=decision,
        subject=cluster_tag,
    )
    return jsonify(result=result)


@app.get("/audit")
def get_audit():
    return jsonify(
        [
            dataclasses.asdict(entry)
            for entry in audit.entries()
        ]
    )


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", 8081)))
