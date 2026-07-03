"""Reads auto-detected exploit candidates (minecore's mine.attack_candidate) and
joins their single-flow templates, shaped for the autopilot. Read-only."""

from __future__ import annotations

import psycopg


def read_candidates(dsn: str) -> list[dict]:
    if not dsn:
        return []
    try:
        with psycopg.connect(dsn, connect_timeout=3) as conn:
            rows = conn.execute(
                """
                SELECT ac.service, ac.cluster_id, ac.port, t.body
                FROM mine.attack_candidate ac
                JOIN mine.template t
                  ON t.service = ac.service AND t.cluster_id = ac.cluster_id
                ORDER BY ac.flag_out DESC
                """
            ).fetchall()
    except Exception:
        return []
    return [
        {
            "sploit": f"cluster:{service}:{cluster_id}",
            "template": body,
            "service": service,
            "port": port,
        }
        for service, cluster_id, port, body in rows
    ]
