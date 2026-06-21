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

	"github.com/gofrs/uuid/v5"
)

const (
	flagIDRefresh      = 30 * time.Second
	snapshotInterval   = 60 * time.Second
	propagateInterval  = 30 * time.Second
	chainSynthInterval = 60 * time.Second
)

type Engine struct {
	db  *db.Database
	cfg Config

	shards        map[string]*clusterStore
	calibrators   map[string]*Calibrator
	serviceByPort map[int]string
	flagRe        *regexp.Regexp
	flagLifetime  int

	flagIDs        []string
	flagIDsAt      time.Time
	lastSnapshotAt time.Time

	templatedAt     map[string]int
	lastSynthAt     time.Time
	lastPropagateAt time.Time

	chains           map[string]*chainAnalyzer // per service
	chainClusters    *chainClusterStore        // shared id allocator
	chainWindow      int64
	chainDFMax       int
	chainMaxSize     int
	lastChainSynthAt time.Time

	scoreboardURL string
	teamID        int
	gameStart     time.Time
	gameTick      time.Duration
}

func New(database *db.Database, cfg Config) *Engine {
	return &Engine{
		db:            database,
		cfg:           cfg,
		shards:        map[string]*clusterStore{},
		calibrators:   map[string]*Calibrator{},
		serviceByPort: config.ServiceByPort(),
		flagRe:        regexp.MustCompile(config.GameFlagRegex()),
		flagLifetime:  config.GameFlagLifetimeTicks() * config.GameTickDurationSec(),
		templatedAt:   map[string]int{},
		chains:        map[string]*chainAnalyzer{},
		chainClusters: newChainClusterStore(),
		chainWindow:   int64(cfg.ChainWindow.Seconds()),
		chainDFMax:    cfg.ChainDFMax,
		chainMaxSize:  cfg.ChainMaxSize,
		scoreboardURL: config.ScoreboardBaseURL(),
		teamID:        config.TeamID(),
		gameStart:     parseGameStart(config.GameStart()),
		gameTick:      time.Duration(config.GameTickDurationSec()) * time.Second,
	}
}

// parseGameStart parses the configured game start time, returning the zero time
// (which disables the heat poller) when it is unset or unrecognized.
func parseGameStart(s string) time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func (e *Engine) Run(ctx context.Context) {
	EnsureSchema(ctx, e.db.Pool())
	e.loadShards(ctx)
	loadChainClusters(ctx, e.db.Pool(), e.chainClusters)
	go e.pollHeatLoop(ctx)
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
		e.maybePropagate(ctx)
		e.maybeChainSynthesize(ctx)

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

	tag := fmt.Sprintf("cluster:%s:%d", service, id)
	e.db.FlowAddTags(f.Id, []string{tag})
	e.tagRole(f, service)
	e.observeChain(f, service, tag, data)
}

// chainShard returns the per-service chain analyzer, creating it on first use.
// Sharding by service keeps the value graph and sessions within one service, so
// a value coincidentally shared across services never links them into a chain.
func (e *Engine) chainShard(service string) *chainAnalyzer {
	a := e.chains[service]
	if a == nil {
		a = newChainAnalyzer(e.chainWindow, e.chainDFMax, e.chainMaxSize, e.chainClusters)
		e.chains[service] = a
	}
	return a
}

// observeChain feeds the flow's high-entropy tokens into its service's chain
// analyzer: values the service hands out (server->client) as producers, values
// the client sends as consumers. Cross-flow reuse of a value links the two flows.
func (e *Engine) observeChain(f *Flow, service, clusterTag string, clientData []byte) {
	serverData, err := e.db.FlowServerData(f.Id)
	if err != nil {
		log.Println("minecore: server data:", err)
		return
	}
	e.chainShard(service).Observe(
		f.Id.String(), f.Time.Unix(), f.DstPort, clusterTag,
		ExtractTokens(serverData), ExtractTokens(clientData),
	)
}

// maybeChainSynthesize emits settled multi-step sessions across every service
// shard: it persists each chain template and tags its member flows.
func (e *Engine) maybeChainSynthesize(ctx context.Context) {
	if !e.lastChainSynthAt.IsZero() && time.Since(e.lastChainSynthAt) < chainSynthInterval {
		return
	}
	e.lastChainSynthAt = time.Now()
	for _, shard := range e.chains {
		for _, sc := range shard.Synthesize() {
			body := chainBody{Pattern: sc.Template, Plan: e.lowerChain(ctx, sc)}
			saveChainBody(ctx, e.db.Pool(), sc.Signature, sc.ID, body)
			for _, member := range sc.Members {
				id, err := uuid.FromString(member)
				if err != nil {
					continue
				}
				e.db.FlowAddTags(id, []string{fmt.Sprintf("chain:%d", sc.ID)})
			}
		}
	}
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
	for service, snaps := range loadCalibratorSnapshots(ctx, e.db.Pool()) {
		e.calibrators[service] = restoreCalibrator(snaps)
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
	for service, calib := range e.calibrators {
		saveCalibratorSnapshots(ctx, e.db.Pool(), service, calib.snapshot())
	}
	e.lastSnapshotAt = time.Now()
}
