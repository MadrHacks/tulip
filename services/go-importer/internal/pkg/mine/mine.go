// Package mine is minecore: the per-flow streaming analysis brain. It reads
// committed flows from Timescale in a horizon-bounded poll cursor, clusters and
// mines them, and writes results back as tags and derived flow items. It is a
// pure analysis engine with no external side-effects (no traffic to opponents,
// no firewall control); those live in the separate actuators.
package mine

import (
	"context"
	"log"
	"time"

	"go-importer/internal/pkg/db"
)

type Engine struct {
	db  *db.Database
	cfg Config
}

func New(database *db.Database, cfg Config) *Engine {
	return &Engine{db: database, cfg: cfg}
}

func (e *Engine) Run(ctx context.Context) {
	EnsureSchema(ctx, e.db.Pool())
	cursor := e.loadCursor(ctx)
	log.Printf("minecore: starting at cursor %s (horizon %s)", cursor, e.cfg.Horizon)

	for {
		if ctx.Err() != nil {
			return
		}

		flows, err := e.readBatch(ctx, cursor)
		if err != nil {
			log.Println("minecore: read batch:", err)
			time.Sleep(e.cfg.PollInterval)
			continue
		}

		for i := range flows {
			e.handle(&flows[i])
		}

		if len(flows) > 0 {
			cursor = flows[len(flows)-1].Id
			e.saveCursor(ctx, cursor)
		}

		// A short batch means we have caught up; a full one means there is more
		// backlog to drain immediately.
		if len(flows) < e.cfg.PollBatch {
			time.Sleep(e.cfg.PollInterval)
		}
	}
}

// handle is the per-flow entry point; analysis stages are added in later phases.
func (e *Engine) handle(f *Flow) {}
