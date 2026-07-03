"""Flask control-API for the gated Replicator. Arm starts OFF; every fire path
goes through the Replicator's own safety checks. There is no raw-fire endpoint."""

import os
import dataclasses
import threading
import time

from flask import Flask, jsonify, request

from actuate import Replicator
from autonomy import AuditLog, Level, Decision
from autopilot import AutoPilot, AutoConfig
from candidates import read_candidates
from config import load_config, load_auto_params
from instantiate import target_allowlist

app = Flask(__name__)
cfg = load_config()

_ARMED = os.environ.get("REPLICATOR_ARMED", "").lower() in ("1", "true", "yes")
replicator = Replicator(cfg, armed=_ARMED)
audit = AuditLog()

# The autonomous loop. It only ever acts when BOTH the replicator is armed (the
# existing gate — nop_proof/replicate return nothing otherwise, so no exploit
# proves and nothing fans out) AND auto mode is armed. Both start off.
_auto = load_auto_params()
autopilot = AutoPilot(
    replicator=replicator,
    candidates_fn=lambda: read_candidates(os.environ.get("TIMESCALE", "")),
    targets_fn=lambda: target_allowlist(cfg.team_id, cfg.team_count, cfg.ip_format, cfg.nop_team),
    cfg=AutoConfig(
        nop_team=cfg.nop_team,
        tick_start=_auto["tick_start"],
        tick_duration=_auto["tick_duration"],
        max_fires_per_step=int(os.environ.get("AUTO_MAX_FIRES_PER_STEP", "10")),
        max_nop_per_step=int(os.environ.get("AUTO_MAX_NOP_PER_STEP", "5")),
        tick_budget=int(os.environ.get("AUTO_TICK_BUDGET", "400")),
        # OFF by default: automatic offense writes only to NOP; real-team fan-out
        # is a human action. Set AUTO_FANOUT=true only for full autonomy.
        auto_fanout=os.environ.get("AUTO_FANOUT", "").lower() in ("1", "true", "yes"),
    ),
    clock=time.time,
)


def _auto_loop():
    interval = float(os.environ.get("AUTO_STEP_INTERVAL", "3"))
    while True:
        try:
            autopilot.step()
        except Exception as exc:  # never let the loop die
            app.logger.warning("autopilot step: %s", exc)
        time.sleep(interval)


threading.Thread(target=_auto_loop, daemon=True).start()


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


@app.post("/chain_nop_proof")
def chain_nop_proof():
    body = request.get_json(force=True) or {}
    sploit = body.get("sploit", "")
    try:
        result = replicator.nop_proof_chain(plan=body["plan"], sploit=sploit, nop_team=cfg.nop_team)
        decision = Decision(allow=True, require_human=False, reason="chain nop verified")
        audit.record(
            capability="offense",
            action="chain_nop_proof",
            level=Level.AUTO,
            decision=decision,
            subject=sploit,
        )
    except ValueError as exc:
        decision = Decision(allow=False, require_human=False, reason=str(exc))
        audit.record(
            capability="offense",
            action="chain_nop_proof",
            level=Level.AUTO,
            decision=decision,
            subject=sploit,
        )
        return jsonify(error=str(exc)), 400
    return jsonify(result=result)


@app.post("/chain_fanout")
def chain_fanout():
    body = request.get_json(force=True) or {}
    sploit = body.get("sploit", "")
    targets = target_allowlist(cfg.team_id, cfg.team_count, cfg.ip_format, cfg.nop_team)
    try:
        results = replicator.fanout_chain(plan=body["plan"], sploit=sploit, targets=targets)
        decision = Decision(allow=True, require_human=False, reason="chain fanout succeeded")
        audit.record(
            capability="offense",
            action="chain_fanout",
            level=Level.AUTO,
            decision=decision,
            subject=sploit,
        )
    except ValueError as exc:
        decision = Decision(allow=False, require_human=False, reason=str(exc))
        audit.record(
            capability="offense",
            action="chain_fanout",
            level=Level.AUTO,
            decision=decision,
            subject=sploit,
        )
        return jsonify(error=str(exc)), 400
    return jsonify(results=results)


@app.post("/auto_arm")
def auto_arm():
    autopilot.armed = True
    autopilot.tripped = False  # arming clears a prior breaker trip
    audit.record(
        capability="offense", action="auto_arm", level=Level.AUTO,
        decision=Decision(allow=True, require_human=False, reason="human-initiated"),
        subject="",
    )
    return jsonify(auto_armed=autopilot.armed, replicator_armed=replicator.armed)


@app.post("/auto_disarm")
def auto_disarm():
    autopilot.armed = False
    audit.record(
        capability="offense", action="auto_disarm", level=Level.MANUAL,
        decision=Decision(allow=True, require_human=False, reason="human-initiated"),
        subject="",
    )
    return jsonify(auto_armed=autopilot.armed)


@app.get("/auto_status")
def auto_status():
    return jsonify(
        auto_armed=autopilot.armed,
        replicator_armed=replicator.armed,
        tripped=autopilot.tripped,
        tick=autopilot.current_tick(),
        proven=[s for s, ok in autopilot.proven.items() if ok],
    )


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
