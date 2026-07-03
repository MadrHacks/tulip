"""Reads auto-detected exploit candidates from minecore's neutral SHAPES
(mine.shape / mine.shape_interactive) and shapes them for the autopilot. Two kinds:

  * "template"    — a single-flow request template (mine.shape.template_body,
                    the align'd {segments,slots} replay skeleton).
  * "interactive" — a stateful single-connection session plan
                    (mine.shape_interactive.plan), for menu-driven services a
                    single request can't express.

A shape is NEUTRAL: it carries the flag_present SIGNAL (its responses leaked a
flag), never a verdict. A candidate here is just a shape carrying that signal;
the replicator's NOP-proof remains the sole arbiter of whether it is a real
exploit. Candidates are gated to services actually under attack (mine.heat with
our_lost > 0). When a shape has both a template and an interactive plan, the
interactive plan wins: it is strictly more capable. Read-only.

sploit ids are "shape:<service>:<shape_id>" (this reader no longer sources the
cluster candidate path — the Go cluster detect keeps running harmlessly)."""

from __future__ import annotations


def _ensure_plan_endpoint(plan, service: str, port: int):
    """Guarantee the plan carries its service+port (the replayer keys the socket
    off them). The Go synthesizer already sets both; this is belt-and-suspenders
    for older rows."""
    if isinstance(plan, dict):
        plan.setdefault("service", service)
        plan.setdefault("port", port)
    return plan


def _shape_candidates(single_rows, interactive_rows) -> list[dict]:
    """Merge single-flow and interactive SHAPE rows into the autopilot candidate
    list, preferring the interactive plan when a shape has both (dedup by sploit).

    single_rows:      (service, shape_id, port, template_body)
    interactive_rows: (service, shape_id, port, plan)
    """
    out: list[dict] = []
    seen: set[str] = set()

    for service, shape_id, port, plan in interactive_rows:
        sploit = f"shape:{service}:{shape_id}"
        if sploit in seen:
            continue
        seen.add(sploit)
        out.append(
            {
                "sploit": sploit,
                "kind": "interactive",
                "plan": _ensure_plan_endpoint(plan, service, port),
                "service": service,
                "port": port,
            }
        )

    for service, shape_id, port, body in single_rows:
        sploit = f"shape:{service}:{shape_id}"
        if sploit in seen:
            continue
        seen.add(sploit)
        out.append(
            {
                "sploit": sploit,
                "kind": "template",
                "template": body,
                "service": service,
                "port": port,
            }
        )

    return out


def read_candidates(dsn: str) -> list[dict]:
    if not dsn:
        return []
    import psycopg  # deferred so the pure shapers stay importable without the driver

    try:
        with psycopg.connect(dsn, connect_timeout=3) as conn:
            # A fresh minecore may not have created the shape tables yet: return
            # nothing rather than erroring. (mine.heat is created alongside
            # mine.shape, so the heat gate below is safe once mine.shape exists.)
            if conn.execute("SELECT to_regclass('mine.shape')").fetchone()[0] is None:
                return []
            # Single-flow shape templates: neutral shapes carrying the flag_present
            # SIGNAL, on services we are losing flags on, that have a replay body.
            single_rows = conn.execute(
                """
                SELECT s.service, s.shape_id, s.port, s.template_body
                FROM mine.shape s
                JOIN mine.heat h ON h.service = s.service AND h.our_lost > 0
                WHERE s.flag_present > 0 AND s.template_body IS NOT NULL
                ORDER BY s.flag_present DESC
                """
            ).fetchall()
            interactive_rows = []
            if conn.execute(
                "SELECT to_regclass('mine.shape_interactive')"
            ).fetchone()[0] is not None:
                interactive_rows = conn.execute(
                    """
                    SELECT si.service, si.shape_id, si.port, si.plan
                    FROM mine.shape_interactive si
                    JOIN mine.heat h ON h.service = si.service AND h.our_lost > 0
                    ORDER BY si.shape_id
                    """
                ).fetchall()
    except Exception:
        return []
    return _shape_candidates(single_rows, interactive_rows)
