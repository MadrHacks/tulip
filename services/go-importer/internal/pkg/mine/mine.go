// Package mine is minecore: the per-flow streaming analysis brain. It reads
// committed flows from Timescale in a horizon-bounded poll cursor, clusters and
// mines them, and writes results back as tags and derived flow items. It is a
// pure analysis engine with no external side-effects (no traffic to opponents,
// no firewall control); those live in the separate actuators.
package mine

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"time"

	"go-importer/internal/pkg/config"
	"go-importer/internal/pkg/db"
)

const (
	flagIDRefresh    = 30 * time.Second
	snapshotInterval = 60 * time.Second
)

type Engine struct {
	db  *db.Database
	cfg Config

	shards        map[string]*clusterStore
	serviceByPort map[int]string
	flagRe        *regexp.Regexp
	flagLifetime  int

	flagIDs        []string
	flagIDsAt      time.Time
	lastSnapshotAt time.Time

	templatedAt map[string]int
	lastSynthAt time.Time
}

func New(database *db.Database, cfg Config) *Engine {
	return &Engine{
		db:            database,
		cfg:           cfg,
		shards:        map[string]*clusterStore{},
		serviceByPort: config.ServiceByPort(),
		flagRe:        regexp.MustCompile(config.GameFlagRegex()),
		flagLifetime:  config.GameFlagLifetimeTicks() * config.GameTickDurationSec(),
		templatedAt:   map[string]int{},
	}
}

func (e *Engine) Run(ctx context.Context) {
	EnsureSchema(ctx, e.db.Pool())
	e.loadShards(ctx)
	cursor := e.loadCursor(ctx)
	log.Printf("minecore: starting at cursor %s (horizon %s)", cursor, e.cfg.Horizon)

	for {
		if ctx.Err() != nil {
			return
		}
		e.refreshFlagIDs()

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
		e.maybeSnapshot(ctx)
		e.maybeSynthesize(ctx)

		// A short batch means we have caught up; a full one means there is more
		// backlog to drain immediately.
		if len(flows) < e.cfg.PollBatch {
			time.Sleep(e.cfg.PollInterval)
		}
	}
}

// handle clusters one flow and tags it with its cluster identity.
func (e *Engine) handle(f *Flow) {
	data, err := e.db.FlowClientData(f.Id)
	if err != nil {
		log.Println("minecore: client data:", err)
		return
	}
	if len(data) == 0 {
		return
	}

	canon := Normalize(data, e.flagRe, e.flagIDs)
	sig, _ := Featurize(canon)

	service := e.serviceName(f.DstPort)
	store := e.shards[service]
	if store == nil {
		store = newClusterStore()
		e.shards[service] = store
	}
	id, _ := store.Assign(sig)

	e.db.FlowAddTags(f.Id, []string{fmt.Sprintf("cluster:%s:%d", service, id)})
}

func (e *Engine) serviceName(port int) string {
	if n := e.serviceByPort[port]; n != "" {
		return n
	}
	return "other"
}

// refreshFlagIDs reloads the live flagId set used for masking, at most once per
// flagIDRefresh interval.
func (e *Engine) refreshFlagIDs() {
	if !e.flagIDsAt.IsZero() && time.Since(e.flagIDsAt) < flagIDRefresh {
		return
	}
	ids, err := e.db.FlagIdsQuery(e.flagLifetime)
	if err != nil {
		log.Println("minecore: flagids:", err)
		return
	}
	contents := make([]string, 0, len(ids))
	for _, x := range ids {
		contents = append(contents, x.Content)
	}
	e.flagIDs = contents
	e.flagIDsAt = time.Now()
}

func (e *Engine) loadShards(ctx context.Context) {
	for service, snaps := range loadClusterSnapshots(ctx, e.db.Pool()) {
		e.shards[service] = restoreClusterStore(snaps)
	}
	e.lastSnapshotAt = time.Now()
}

func (e *Engine) maybeSnapshot(ctx context.Context) {
	if !e.lastSnapshotAt.IsZero() && time.Since(e.lastSnapshotAt) < snapshotInterval {
		return
	}
	for service, store := range e.shards {
		saveClusterSnapshots(ctx, e.db.Pool(), service, store.snapshot())
	}
	e.lastSnapshotAt = time.Now()
}
