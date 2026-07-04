// Package mine is minecore: the per-flow streaming analysis brain. It reads
// committed flows from Timescale in a horizon-bounded poll cursor, mines them
// into request shapes, and writes results back as tags and derived flow items.
// It is a pure analysis engine with no external side-effects (no traffic to
// opponents, no firewall control); those live in the separate actuators.
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

	shapeStore    *ShapeStore // neutral request-shape path: the sole request-mining substrate
	serviceByPort map[int]string
	resolver      *serviceResolver
	flagRe        *regexp.Regexp
	flagLifetime  int

	flagIDs        []string
	fidRe          *regexp.Regexp // precompiled flagId matcher, rebuilt on refresh
	flagIDsAt      time.Time
	lastSnapshotAt time.Time
	caughtUpOnce   bool // fired the first (warm) refined snapshot once backlog drained

	// persistedRefined tracks, per service, the crisp refined ids this process last
	// wrote to mine.shape, so a refined shape that stops being produced (a split
	// that merged, an evicted parent) is reconciled away without wiping pre-restart
	// rows on the first post-restart snapshot.
	persistedRefined map[string]map[int64]struct{}

	lastPropagateAt time.Time
	verdicts        map[string]string // cluster tag -> advisory verdict suggestion

	lastDetectAt            time.Time
	warnedServiceMismatch   bool            // one-shot: config names don't match the scoreboard
	shapeInteractiveSynthed map[string]bool // "service:shape_id" attempted once for shape interactive synthesis

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
	store := NewShapeStore(cfg.MaxShapes)
	store.SetSplitParams(cfg.SplitCard, cfg.SplitVariantCap)
	return &Engine{
		db:                      database,
		cfg:                     cfg,
		shapeStore:              store,
		serviceByPort:           config.ServiceByPort(),
		resolver:                newServiceResolver(config.ServiceDefs()),
		flagRe:                  regexp.MustCompile(config.GameFlagRegex()),
		flagLifetime:            config.GameFlagLifetimeTicks() * config.GameTickDurationSec(),
		verdicts:                map[string]string{},
		persistedRefined:        map[string]map[int64]struct{}{},
		shapeInteractiveSynthed: map[string]bool{},
		chains:                  map[string]*chainAnalyzer{},
		chainClusters:           newChainClusterStore(),
		chainWindow:             int64(cfg.ChainWindow.Seconds()),
		chainDFMax:              cfg.ChainDFMax,
		chainMaxSize:            cfg.ChainMaxSize,
		scoreboardURL:           config.ScoreboardBaseURL(),
		teamID:                  config.TeamID(),
		gameStart:               parseGameStart(config.GameStart()),
		gameTick:                time.Duration(config.GameTickDurationSec()) * time.Second,
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
	e.loadShapes(ctx)
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
		e.maybePropagate(ctx)
		e.maybeChainSynthesize(ctx)
		e.maybeDetect(ctx)

		// A short batch means we have caught up; a full one means there is more
		// backlog to drain immediately.
		if len(flows) < e.cfg.PollBatch {
			// The first time we drain the backlog, snapshot immediately: shapes are
			// now warm, so crisp candidates land in mine.shape without waiting a full
			// snapshot interval (a fresh minecore otherwise has no candidates for ~a
			// minute after every restart).
			if !e.caughtUpOnce {
				e.caughtUpOnce = true
				e.snapshotShapes(ctx)
				e.lastSnapshotAt = time.Now()
			}
			time.Sleep(e.cfg.PollInterval)
		}
	}
}

// handle mines one flow and tags it with its neutral shape identities. It
// fetches the flow's most-decoded bytes for both directions in a single query,
// so shape and chain analysis both run on the topmost representation (TLS-
// decrypted, base64-decoded, or whatever the flow's deepest decoder produced).
func (e *Engine) handle(f *Flow) {
	client, server, err := e.db.FlowAnalysisData(f.Id)
	if err != nil {
		log.Println("minecore: flow data:", err)
		return
	}
	if len(client) == 0 {
		return
	}

	t := f.Time.Unix()
	service := e.serviceName(f.DstPort)

	// Neutral shape path: fold the flow's ordered messages into the shape store
	// and write its shape:/session: tags. This is the sole request-mining
	// substrate (the old MinHash cluster path has been retired).
	tags := e.shapeTags(f, service, t)
	e.db.FlowAddTags(f.Id, tags)
	// The chain analyzer keys each step by the flow's single shape identity; the
	// runnable-plan lowering later fetches that shape's replay template.
	if !e.cfg.ChainDisable {
		e.observeChain(f, service, primaryShapeTag(tags), client, server)
	}
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
// stepTag is the flow's shape identity, carried as each step's single-flow key.
func (e *Engine) observeChain(f *Flow, service, stepTag string, clientData, serverData []byte) {
	e.chainShard(service).Observe(
		f.Id.String(), f.Time.Unix(), f.DstPort, stepTag,
		ExtractTokens(serverData), ExtractTokens(clientData),
	)
}

// maybeChainSynthesize emits settled multi-step sessions across every service
// shard: it persists each chain template and tags its member flows.
func (e *Engine) maybeChainSynthesize(ctx context.Context) {
	if e.cfg.ChainDisable {
		return
	}
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
	e.fidRe = buildFlagIDRegex(contents)
	e.flagIDsAt = time.Now()
}

// loadShapes restores the shape store from mine.shape at startup: rebuilding
// each shard's Drain from the persisted templates keeps shape ids stable across
// a restart.
func (e *Engine) loadShapes(ctx context.Context) {
	e.shapeStore = restoreShapeStore(loadShapeSnapshots(ctx, e.db.Pool()), e.cfg.MaxShapes)
	e.shapeStore.SetSplitParams(e.cfg.SplitCard, e.cfg.SplitVariantCap)
	e.lastSnapshotAt = time.Now()
}

func (e *Engine) maybeSnapshot(ctx context.Context) {
	if !e.lastSnapshotAt.IsZero() && time.Since(e.lastSnapshotAt) < snapshotInterval {
		return
	}
	e.snapshotShapes(ctx)
	e.lastSnapshotAt = time.Now()
}
