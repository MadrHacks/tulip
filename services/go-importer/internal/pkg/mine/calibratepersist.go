package mine

import (
	"context"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

// loadCalibratorSnapshots reads persisted per-source checker stats, grouped by
// service.
func loadCalibratorSnapshots(ctx context.Context, pool *pgxpool.Pool) map[string][]sourceSnapshot {
	out := map[string][]sourceSnapshot{}
	rows, err := pool.Query(ctx, `
		SELECT service, source, count, flag_outs, last_seen, has_last, gap_sum, gap_sq_sum, gap_count
		FROM mine.calibrator
	`)
	if err != nil {
		log.Println("minecore: load calibrators:", err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var service string
		var s sourceSnapshot
		if err := rows.Scan(&service, &s.source, &s.count, &s.flagOuts, &s.lastSeen,
			&s.hasLast, &s.gapSum, &s.gapSqSum, &s.gapCount); err != nil {
			log.Println("minecore: scan calibrator:", err)
			return out
		}
		out[service] = append(out[service], s)
	}
	return out
}

// deleteCalibratorSources drops evicted sources' persisted rows.
func deleteCalibratorSources(ctx context.Context, pool *pgxpool.Pool, service string, sources []string) {
	if len(sources) == 0 {
		return
	}
	_, err := pool.Exec(ctx,
		`DELETE FROM mine.calibrator WHERE service = $1 AND source = ANY($2)`, service, sources)
	if err != nil {
		log.Println("minecore: delete calibrator sources:", err)
	}
}

// saveCalibratorSnapshots upserts one service's per-source checker stats.
func saveCalibratorSnapshots(ctx context.Context, pool *pgxpool.Pool, service string, snaps []sourceSnapshot) {
	for _, s := range snaps {
		_, err := pool.Exec(ctx, `
			INSERT INTO mine.calibrator
				(service, source, count, flag_outs, last_seen, has_last, gap_sum, gap_sq_sum, gap_count)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (service, source) DO UPDATE SET
				count = excluded.count, flag_outs = excluded.flag_outs,
				last_seen = excluded.last_seen, has_last = excluded.has_last,
				gap_sum = excluded.gap_sum, gap_sq_sum = excluded.gap_sq_sum,
				gap_count = excluded.gap_count
		`, service, s.source, s.count, s.flagOuts, s.lastSeen, s.hasLast, s.gapSum, s.gapSqSum, s.gapCount)
		if err != nil {
			log.Println("minecore: save calibrator:", err)
			return
		}
	}
}
