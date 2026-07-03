"""Reads auto-detected exploit candidates (minecore's mine.attack_candidate),
joins their replay artifacts, and shapes them for the autopilot. Two kinds:

  * "template"    — a single-flow request template (mine.template).
  * "interactive" — a stateful single-connection session plan
                    (mine.interactive_template), for menu-driven services a
                    single request can't express.

When a cluster has both, the interactive plan wins: it is strictly more capable.
Read-only."""

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
    """Merge single-flow and interactive rows into the autopilot candidate list,
    preferring the interactive plan when a cluster has both (dedup by sploit).

    single_rows:      (service, cluster_id, port, body)
    interactive_rows: (service, cluster_id, port, plan)
    """
    out: list[dict] = []
    seen: set[str] = set()

    for service, cluster_id, port, plan in interactive_rows:
        sploit = f"cluster:{service}:{cluster_id}"
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

    for service, cluster_id, port, body in single_rows:
        sploit = f"cluster:{service}:{cluster_id}"
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
            single_rows = conn.execute(
                """
                SELECT ac.service, ac.cluster_id, ac.port, t.body
                FROM mine.attack_candidate ac
                JOIN mine.template t
                  ON t.service = ac.service AND t.cluster_id = ac.cluster_id
                ORDER BY ac.flag_out DESC
                """
            ).fetchall()
            interactive_rows = conn.execute(
                """
                SELECT ac.service, ac.cluster_id, ac.port, it.plan
                FROM mine.attack_candidate ac
                JOIN mine.interactive_template it
                  ON it.service = ac.service AND it.cluster_id = ac.cluster_id
                ORDER BY ac.flag_out DESC
                """
            ).fetchall()
    except Exception:
        return []
    return _shape_candidates(single_rows, interactive_rows)
