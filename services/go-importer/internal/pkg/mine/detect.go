package mine

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const detectInterval = 30 * time.Second

// maybeDetect auto-flags exploit-candidate clusters. The rule is fully NAT-robust
// — it uses no source IP: on a service where the scoreboard shows we are losing
// flags (heat), any cluster whose flows leak a flag (flagOut) is a candidate
// attack. Detection is deliberately liberal; the replicator's NOP-proof gate is
// the precision filter, so a mis-flagged checker retrieve simply fails to capture
// a flag at NOP and is never fanned out. Candidates are persisted for the
// autonomous replicator to act on.
func (e *Engine) maybeDetect(ctx context.Context) {
	if !e.lastDetectAt.IsZero() && time.Since(e.lastDetectAt) < detectInterval {
		return
	}
	e.lastDetectAt = time.Now()

	lost := loadHeatLoss(ctx, e.db.Pool())
	if len(lost) == 0 {
		return
	}
	e.warnOnServiceNameMismatch(lost)
	for service, store := range e.shards {
		if lost[service] <= 0 {
			continue
		}
		for id, c := range store.clusters {
			if c.flagOut > 0 {
				saveAttackCandidate(ctx, e.db.Pool(), service, id, c.flagOut, c.n, c.firstSeen, c.port)
			}
		}
	}
}

// warnOnServiceNameMismatch fails loud at the boundary where the two service-name
// sources meet: heat is keyed by the scoreboard's names, clusters by the
// services.yml names. If a service the scoreboard says we're losing has no
// matching cluster shard, the config names don't line up with the scoreboard —
// which would otherwise silently detect nothing. We warn once rather than
// tolerating the mismatch downstream.
func (e *Engine) warnOnServiceNameMismatch(lost map[string]int) {
	if e.warnedServiceMismatch {
		return
	}
	for svc := range lost {
		if _, ok := e.shards[svc]; ok {
			return // at least one lines up; config is consistent
		}
	}
	e.warnedServiceMismatch = true
	scoreboard := make([]string, 0, len(lost))
	for s := range lost {
		scoreboard = append(scoreboard, s)
	}
	configured := make([]string, 0, len(e.shards))
	for s := range e.shards {
		configured = append(configured, s)
	}
	log.Printf("minecore: scoreboard service names %v do not match any configured service %v — "+
		"align services.yml names exactly with the scoreboard (names are matched, not normalized)",
		scoreboard, configured)
}

// loadHeatLoss returns service -> flags we lost, for services under attack.
func loadHeatLoss(ctx context.Context, pool *pgxpool.Pool) map[string]int {
	out := map[string]int{}
	rows, err := pool.Query(ctx, `SELECT service, our_lost FROM mine.heat WHERE our_lost > 0`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		var l int
		if rows.Scan(&s, &l) == nil {
			out[s] = l
		}
	}
	return out
}

// saveAttackCandidate upserts a detected candidate for the replicator to pick up.
func saveAttackCandidate(ctx context.Context, pool *pgxpool.Pool, service string, id int64, flagOut, n int, firstSeen int64, port int) {
	_, err := pool.Exec(ctx, `
		INSERT INTO mine.attack_candidate (service, cluster_id, flag_out, n, first_seen, port)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (service, cluster_id) DO UPDATE SET
			flag_out = excluded.flag_out, n = excluded.n, port = excluded.port, detected_at = now()
	`, service, id, flagOut, n, firstSeen, port)
	if err != nil {
		log.Println("minecore: save candidate:", err)
	}
}
