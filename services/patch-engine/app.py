"""Flask control-API for the gated PatchEngine. Arm starts OFF; rule activation
goes through the engine's own safety checks (synthesis refuses SLA-killing rules,
rules are created inactive, enabling requires armed)."""

import os

from flask import Flask, jsonify, request

from deploy import PatchEngine
from firegex_client import FiregexClient

app = Flask(__name__)

firegex = FiregexClient(
    base_url=os.environ.get("FIREGEX_URL", "http://localhost:4444"),
    password=os.environ.get("FIREGEX_PASSWORD", ""),
)

_ARMED = os.environ.get("PATCH_ENGINE_ARMED", "").lower() in ("1", "true", "yes")
engine = PatchEngine(firegex, armed=_ARMED)


@app.get("/status")
def status():
    return jsonify(armed=engine.armed)


@app.post("/arm")
def arm():
    engine.armed = True  # the human gate
    return jsonify(armed=engine.armed)


@app.post("/disarm")
def disarm():
    engine.armed = False
    return jsonify(armed=engine.armed)


@app.post("/propose")
def propose():
    body = request.get_json(force=True) or {}
    regex_id = engine.propose(
        cluster_tag=body["cluster_tag"], const_tokens=body["const_tokens"],
        benign_samples=body["benign_samples"], service_id=body["service_id"],
        mode=body.get("mode", "B"),
    )
    return jsonify(regex_id=regex_id)


@app.post("/arm_rule")
def arm_rule():
    body = request.get_json(force=True) or {}
    return jsonify(result=engine.arm_rule(cluster_tag=body["cluster_tag"]))


@app.post("/rollback")
def rollback():
    body = request.get_json(force=True) or {}
    return jsonify(result=engine.rollback(cluster_tag=body["cluster_tag"]))


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", 8081)))
