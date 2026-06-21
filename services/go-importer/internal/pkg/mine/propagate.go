package mine

import (
	"context"
	"log"
	"time"
)

// propagateHorizonSecs bounds verdict propagation to recently packed flows.
const propagateHorizonSecs = 1200

// maybePropagate runs the propagation pass at most once per propagateInterval.
func (e *Engine) maybePropagate(ctx context.Context) {
	if !e.lastPropagateAt.IsZero() && time.Since(e.lastPropagateAt) < propagateInterval {
		return
	}
	e.propagateVerdicts(ctx)
	e.lastPropagateAt = time.Now()
}

// propagateVerdicts is one semi-supervised pass: for every cluster carrying a
// single operator verdict (verdict:attack or verdict:benign) on some recent
// flow, it stamps the matching advisory suggestion (verdict:attack? /
// verdict:benign?) onto that cluster's other recent members that have no verdict
// yet. Clusters with BOTH operator verdicts are ambiguous and left untouched.
// The ?-suffixed tags are advisory and never count as operator verdicts.
func (e *Engine) propagateVerdicts(ctx context.Context) {
	const sql = `
WITH verdicted AS (
    SELECT DISTINCT
        ct.tag AS cluster_tag,
        CASE vt.tag
            WHEN 'verdict:attack' THEN 'verdict:attack?'
            ELSE 'verdict:benign?'
        END AS suggestion
    FROM flow f
    CROSS JOIN LATERAL jsonb_array_elements_text(f.tags) AS vt(tag)
    CROSS JOIN LATERAL jsonb_array_elements_text(f.tags) AS ct(tag)
    WHERE f.id > fid_pack_low(now() - make_interval(secs => $1))
      AND vt.tag IN ('verdict:attack', 'verdict:benign')
      AND ct.tag LIKE 'cluster:%'
),
resolved AS (
    SELECT cluster_tag, min(suggestion) AS suggestion
    FROM verdicted
    GROUP BY cluster_tag
    HAVING count(DISTINCT suggestion) = 1
)
UPDATE flow f
SET tags = jsonb_unique(f.tags || jsonb_build_array(r.suggestion::text))
FROM resolved r
WHERE f.id > fid_pack_low(now() - make_interval(secs => $1))
  AND f.tags ? r.cluster_tag
  AND NOT (f.tags ? 'verdict:attack')
  AND NOT (f.tags ? 'verdict:benign')
  AND NOT (f.tags ? 'verdict:attack?')
  AND NOT (f.tags ? 'verdict:benign?')
`
	if _, err := e.db.Pool().Exec(ctx, sql, propagateHorizonSecs); err != nil {
		log.Printf("mine: propagateVerdicts: %v", err)
	}
}
