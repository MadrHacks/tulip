package mine

import (
	"context"
	"encoding/json"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB glue for ShapeStore snapshots (mine.shape). Mirrors persist.go's cluster
// persistence. Not yet wired into the engine loop — the next integration step
// calls these from the snapshot/eviction hooks, exactly as mine.go does for
// clusters.

// loadShapeSnapshots reads persisted shapes, grouped by service, for
// restoreShapeStore.
func loadShapeSnapshots(ctx context.Context, pool *pgxpool.Pool) map[string][]shapeSnapshot {
	out := map[string][]shapeSnapshot{}
	rows, err := pool.Query(ctx, `
		SELECT service, shape_id, template, members, size_bucket_sum,
			flag_present, flag_in, actors, first_seen, last_seen, port, template_body
		FROM mine.shape
	`)
	if err != nil {
		log.Println("minecore: load shapes:", err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var service string
		var s shapeSnapshot
		var actors []byte
		if err := rows.Scan(&service, &s.ShapeID, &s.Template, &s.Members, &s.SizeBucketSum,
			&s.FlagPresent, &s.FlagIn, &actors, &s.FirstSeen, &s.LastSeen, &s.Port, &s.TemplateBody); err != nil {
			log.Println("minecore: scan shape:", err)
			return out
		}
		s.Actors = map[string]int{}
		if len(actors) > 0 {
			if err := json.Unmarshal(actors, &s.Actors); err != nil {
				log.Println("minecore: unmarshal shape actors:", err)
			}
		}
		out[service] = append(out[service], s)
	}
	return out
}

// saveShapeSnapshots upserts one service's shapes.
func saveShapeSnapshots(ctx context.Context, pool *pgxpool.Pool, service string, snaps []shapeSnapshot) {
	for _, s := range snaps {
		actors, err := json.Marshal(s.Actors)
		if err != nil {
			log.Println("minecore: marshal shape actors:", err)
			continue
		}
		_, err = pool.Exec(ctx, `
			INSERT INTO mine.shape
				(service, shape_id, template, members, size_bucket_sum,
				 flag_present, flag_in, actors, first_seen, last_seen, port, template_body)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (service, shape_id) DO UPDATE SET
				template = excluded.template, members = excluded.members,
				size_bucket_sum = excluded.size_bucket_sum,
				flag_present = excluded.flag_present, flag_in = excluded.flag_in,
				actors = excluded.actors, first_seen = excluded.first_seen,
				last_seen = excluded.last_seen, port = excluded.port,
				template_body = COALESCE(excluded.template_body, mine.shape.template_body)
		`, service, s.ShapeID, s.Template, s.Members, s.SizeBucketSum,
			s.FlagPresent, s.FlagIn, actors, s.FirstSeen, s.LastSeen, s.Port, templateBodyArg(s.TemplateBody))
		if err != nil {
			log.Println("minecore: save shape:", err)
			return
		}
	}
}

// templateBodyArg maps a shape's replay-template body to its SQL argument: the
// raw jsonb bytes, or an explicit nil (SQL NULL) when the shape has no template
// yet — so the upsert's COALESCE keeps any previously-persisted template instead
// of clobbering it with an empty value.
func templateBodyArg(body []byte) any {
	if len(body) == 0 {
		return nil
	}
	return body
}

// deleteShapes drops evicted shapes' persisted rows so a restart does not reload
// them.
func deleteShapes(ctx context.Context, pool *pgxpool.Pool, service string, ids []int) {
	if len(ids) == 0 {
		return
	}
	_, err := pool.Exec(ctx,
		`DELETE FROM mine.shape WHERE service = $1 AND shape_id = ANY($2)`, service, ids)
	if err != nil {
		log.Println("minecore: delete shapes:", err)
	}
}
