package mine

import (
	"context"
	"encoding/binary"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

func minhashBytes(m MinHash) []byte {
	b := make([]byte, minhashN*8)
	for i, v := range m {
		binary.LittleEndian.PutUint64(b[i*8:], v)
	}
	return b
}

func minhashFromBytes(b []byte) MinHash {
	var m MinHash
	for i := range m {
		if (i+1)*8 <= len(b) {
			m[i] = binary.LittleEndian.Uint64(b[i*8:])
		}
	}
	return m
}

// loadClusterSnapshots reads persisted clusters, grouped by service.
func loadClusterSnapshots(ctx context.Context, pool *pgxpool.Pool) map[string][]clusterSnapshot {
	out := map[string][]clusterSnapshot{}
	rows, err := pool.Query(ctx, `SELECT service, id, rep, core, core_set, n FROM mine.cluster`)
	if err != nil {
		log.Println("minecore: load clusters:", err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var service string
		var s clusterSnapshot
		var rep, core []byte
		if err := rows.Scan(&service, &s.id, &rep, &core, &s.coreSet, &s.n); err != nil {
			log.Println("minecore: scan cluster:", err)
			return out
		}
		s.rep = minhashFromBytes(rep)
		s.core = minhashFromBytes(core)
		out[service] = append(out[service], s)
	}
	return out
}

// saveClusterSnapshots upserts one service's clusters.
func saveClusterSnapshots(ctx context.Context, pool *pgxpool.Pool, service string, snaps []clusterSnapshot) {
	for _, s := range snaps {
		_, err := pool.Exec(ctx, `
			INSERT INTO mine.cluster (service, id, rep, core, core_set, n)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (service, id) DO UPDATE SET
				rep = excluded.rep, core = excluded.core,
				core_set = excluded.core_set, n = excluded.n
		`, service, s.id, minhashBytes(s.rep), minhashBytes(s.core), s.coreSet, s.n)
		if err != nil {
			log.Println("minecore: save cluster:", err)
			return
		}
	}
}
