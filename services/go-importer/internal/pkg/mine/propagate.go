package mine

import (
	"context"
	"log"
	"time"
)

// propagateHorizonSecs bounds verdict propagation to recently packed flows.
const propagateHorizonSecs = 1200

// maybePropagate keeps the in-memory verdict map current and back-fills any
// newly labeled cluster's existing members. Fresh flows inherit a cluster's
// verdict incrementally in handle (an O(1) map lookup, one extra tag on the same
// write), so this periodic pass is cheap: a small read over only the operator-
// labeled flows, plus a targeted update that runs solely when a label first
// appears — never a full-corpus rescan.
func (e *Engine) maybePropagate(ctx context.Context) {
	if !e.lastPropagateAt.IsZero() && time.Since(e.lastPropagateAt) < propagateInterval {
		return
	}
	e.lastPropagateAt = time.Now()

	next := e.readVerdicts(ctx)
	for clusterTag, suggestion := range next {
		if e.verdicts[clusterTag] != suggestion {
			e.backfillCluster(ctx, clusterTag, suggestion)
		}
	}
	e.verdicts = next
}

// readVerdicts returns each cluster's advisory suggestion (verdict:attack? /
// verdict:benign?) derived from operator verdicts on recent flows. Only flows
// that actually carry a verdict tag are expanded, so the cost tracks the number
// of labeled flows (few), not traffic volume. A cluster with both verdicts is
// ambiguous and omitted.
func (e *Engine) readVerdicts(ctx context.Context) map[string]string {
	const sql = `
SELECT cluster_tag, min(suggestion) AS suggestion FROM (
    SELECT ct.tag AS cluster_tag,
        CASE vt.tag WHEN 'verdict:attack' THEN 'verdict:attack?' ELSE 'verdict:benign?' END AS suggestion
    FROM flow f
    CROSS JOIN LATERAL jsonb_array_elements_text(f.tags) AS vt(tag)
    CROSS JOIN LATERAL jsonb_array_elements_text(f.tags) AS ct(tag)
    WHERE f.id > fid_pack_low(now() - make_interval(secs => $1))
      AND f.tags ?| array['verdict:attack', 'verdict:benign']
      AND vt.tag IN ('verdict:attack', 'verdict:benign')
      AND ct.tag LIKE 'cluster:%'
) s
GROUP BY cluster_tag
HAVING count(DISTINCT suggestion) = 1
`
	out := map[string]string{}
	rows, err := e.db.Pool().Query(ctx, sql, propagateHorizonSecs)
	if err != nil {
		log.Printf("mine: readVerdicts: %v", err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var tag, suggestion string
		if err := rows.Scan(&tag, &suggestion); err != nil {
			log.Printf("mine: readVerdicts scan: %v", err)
			return e.verdicts // keep the last good map on a partial read
		}
		out[tag] = suggestion
	}
	return out
}

// backfillCluster stamps a cluster's advisory suggestion onto its existing,
// still-unlabeled recent members. Targeted by the cluster tag (GIN-indexed), it
// runs only when a label first appears, not on every pass.
func (e *Engine) backfillCluster(ctx context.Context, clusterTag, suggestion string) {
	const sql = `
UPDATE flow f
SET tags = jsonb_unique(f.tags || jsonb_build_array($2::text))
WHERE f.id > fid_pack_low(now() - make_interval(secs => $3))
  AND f.tags ? $1
  AND NOT (f.tags ? 'verdict:attack')
  AND NOT (f.tags ? 'verdict:benign')
  AND NOT (f.tags ? 'verdict:attack?')
  AND NOT (f.tags ? 'verdict:benign?')
`
	if _, err := e.db.Pool().Exec(ctx, sql, clusterTag, suggestion, propagateHorizonSecs); err != nil {
		log.Printf("mine: backfillCluster %s: %v", clusterTag, err)
	}
}
