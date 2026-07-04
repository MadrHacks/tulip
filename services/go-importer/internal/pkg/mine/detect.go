package mine

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const detectInterval = 30 * time.Second

// maybeDetect pursues exploit-candidate SHAPES. The rule is fully NAT-robust —
// it uses no source IP: on a service where the scoreboard shows we are losing
// flags (heat), every neutral shape carrying the flag_present SIGNAL is pursued
// once for an interactive session plan. This is the SOURCE the autonomous
// candidate reader consumes; it stays NEUTRAL — flag_present is a signal, and
// the replicator's NOP-proof remains the sole arbiter of a real exploit. The
// single-flow shape template is already persisted by the snapshot pass
// (mine.shape.template_body), so nothing extra is written here for it.
// Detection is deliberately liberal; the replicator's NOP-proof gate is the
// precision filter, so a mis-flagged checker retrieve simply fails to capture a
// flag at NOP and is never fanned out.
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
	for service := range lost {
		if lost[service] <= 0 {
			continue
		}
		for _, fs := range e.shapeStore.RefinedFlagShapes(service) {
			e.maybeSynthInteractiveShape(ctx, service, fs.ID, fs.Port)
		}
	}
}

// warnOnServiceNameMismatch fails loud at the boundary where the two service-name
// sources meet: heat is keyed by the scoreboard's names, shapes by the
// services.yml names. If a service the scoreboard says we're losing has no
// matching shape shard, the config names don't line up with the scoreboard —
// which would otherwise silently detect nothing. We warn once rather than
// tolerating the mismatch downstream.
func (e *Engine) warnOnServiceNameMismatch(lost map[string]int) {
	if e.warnedServiceMismatch {
		return
	}
	configured := e.shapeStore.Services()
	have := make(map[string]bool, len(configured))
	for _, s := range configured {
		have[s] = true
	}
	for svc := range lost {
		if have[svc] {
			return // at least one lines up; config is consistent
		}
	}
	e.warnedServiceMismatch = true
	scoreboard := make([]string, 0, len(lost))
	for s := range lost {
		scoreboard = append(scoreboard, s)
	}
	log.Printf("minecore: scoreboard service names %v matched no configured service %v even after "+
		"fuzzy matching — set an explicit scoreboard_name in services.yml for the odd one out",
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
