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
	shapeStore    *ShapeStore // parallel neutral request-shape path (runs alongside shards)
	calibrators   map[string]*Calibrator
	serviceByPort map[int]string
	resolver      *serviceResolver
	flagRe        *regexp.Regexp
	flagLifetime  int

	flagIDs        []string
	fidRe          *regexp.Regexp // precompiled flagId matcher, rebuilt on refresh
	flagIDsAt      time.Time
	lastSnapshotAt time.Time

	templatedAt     map[string]int
	lastSynthAt     time.Time
	lastPropagateAt time.Time
	verdicts        map[string]string // cluster tag -> advisory verdict suggestion

	dataClock             int64 // newest flow time seen (unix sec), drives eviction
	lastDetectAt          time.Time
	warnedServiceMismatch bool            // one-shot: config names don't match the scoreboard
	interactiveSynthed    map[string]bool // "service:cluster_id" attempted once for interactive synthesis

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
		db:                 database,
		cfg:                cfg,
		shards:             map[string]*clusterStore{},
		shapeStore:         NewShapeStore(cfg.MaxShapes),
		calibrators:        map[string]*Calibrator{},
		serviceByPort:      config.ServiceByPort(),
		resolver:           newServiceResolver(config.ServiceDefs()),
		flagRe:             regexp.MustCompile(config.GameFlagRegex()),
		flagLifetime:       config.GameFlagLifetimeTicks() * config.GameTickDurationSec(),
		templatedAt:        map[string]int{},
		verdicts:           map[string]string{},
		interactiveSynthed: map[string]bool{},
		chains:             map[string]*chainAnalyzer{},
		chainClusters:      newChainClusterStore(),
		chainWindow:        int64(cfg.ChainWindow.Seconds()),
		chainDFMax:         cfg.ChainDFMax,
		chainMaxSize:       cfg.ChainMaxSize,
		scoreboardURL:      config.ScoreboardBaseURL(),
		teamID:             config.TeamID(),
		gameStart:          parseGameStart(config.GameStart()),
		gameTick:           time.Duration(config.GameTickDurationSec()) * time.Second,
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
		e.maybeDetect(ctx)

		// A short batch means we have caught up; a full one means there is more
		// backlog to drain immediately.
		if len(flows) < e.cfg.PollBatch {
			time.Sleep(e.cfg.PollInterval)
		}
	}
}

// handle clusters one flow and tags it with its cluster identity. It fetches the
// flow's most-decoded bytes for both directions in a single query, so clustering
// and chain analysis both run on the topmost representation (TLS-decrypted,
// base64-decoded, or whatever the flow's deepest decoder produced).
func (e *Engine) handle(f *Flow) {
	client, server, err := e.db.FlowAnalysisData(f.Id)
	if err != nil {
		log.Println("minecore: flow data:", err)
		return
	}
	if len(client) == 0 {
		return
	}

	// Truncate the canonical form before masking so both stay cheap on large
	// bodies: 8 KB captures a request's shape, and masking then runs over that.
	canon := canonical(client)
	if len(canon) > maxFeatureBytes {
		canon = canon[:maxFeatureBytes]
	}
	sig, _ := Featurize(maskValues(canon, e.flagRe, e.fidRe))

	t := f.Time.Unix()
	if t > e.dataClock {
		e.dataClock = t
	}

	service := e.serviceName(f.DstPort)
	store := e.shards[service]
	if store == nil {
		store = newClusterStore(e.cfg.MergeThreshold)
		e.shards[service] = store
	}
	id, _ := store.Assign(sig, t, f.FlagsOut > 0, f.DstPort)

	clusterTag := fmt.Sprintf("cluster:%s:%d", service, id)
	// role:* tags are intentionally not emitted: under NAT the checker/exploit
	// calibration is a wrong-category signal (pure cockpit noise). The calibrator
	// plumbing (roleTag/calibrators) is retained pending a larger rework.
	tags := []string{clusterTag}
	// A fresh flow matching a cluster the operator already judged inherits that
	// verdict immediately, in the same write — no periodic bulk propagation.
	if sugg := e.verdicts[clusterTag]; sugg != "" {
		tags = append(tags, sugg)
	}
	// Parallel shape path: fold the flow's ordered messages into the neutral
	// shape store and add its shape:/session: tags to the SAME write. This runs
	// alongside — never in place of — the cluster tagging above.
	tags = append(tags, e.shapeTags(f, service, t)...)
	e.db.FlowAddTags(f.Id, tags)
	if !e.cfg.ChainDisable {
		e.observeChain(f, service, clusterTag, client, server)
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
func (e *Engine) observeChain(f *Flow, service, clusterTag string, clientData, serverData []byte) {
	e.chainShard(service).Observe(
		f.Id.String(), f.Time.Unix(), f.DstPort, clusterTag,
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

func (e *Engine) loadShards(ctx context.Context) {
	// Skip clusters last seen before the horizon: a restart after downtime must
	// not reload long-dead clusters into RAM.
	floor := time.Now().Unix() - int64(e.cfg.Horizon.Seconds())
	for service, snaps := range loadClusterSnapshots(ctx, e.db.Pool()) {
		e.shards[service] = restoreClusterStore(snaps, floor, e.cfg.MergeThreshold)
	}
	for service, snaps := range loadCalibratorSnapshots(ctx, e.db.Pool()) {
		e.calibrators[service] = restoreCalibrator(snaps)
	}
	// Restore the parallel shape store from mine.shape: rebuilding each shard's
	// Drain from the persisted templates keeps shape ids stable across a restart.
	e.shapeStore = restoreShapeStore(loadShapeSnapshots(ctx, e.db.Pool()), e.cfg.MaxShapes)
	e.lastSnapshotAt = time.Now()
}

func (e *Engine) maybeSnapshot(ctx context.Context) {
	if !e.lastSnapshotAt.IsZero() && time.Since(e.lastSnapshotAt) < snapshotInterval {
		return
	}
	e.evictClusters(ctx)
	before := e.dataClock - int64(e.cfg.Horizon.Seconds())
	for service, store := range e.shards {
		saveClusterSnapshots(ctx, e.db.Pool(), service, store.snapshot())
	}
	for service, calib := range e.calibrators {
		if gone := calib.evictStale(before); len(gone) > 0 {
			deleteCalibratorSources(ctx, e.db.Pool(), service, gone)
		}
		saveCalibratorSnapshots(ctx, e.db.Pool(), service, calib.snapshot())
	}
	e.snapshotShapes(ctx)
	e.lastSnapshotAt = time.Now()
}

// evictClusters bounds each service shard: it drops clusters not seen within the
// horizon (their flows are past the read window) and enforces the hard cap by
// least-recently-seen, deleting the evicted rows and their template bookkeeping.
func (e *Engine) evictClusters(ctx context.Context) {
	before := e.dataClock - int64(e.cfg.Horizon.Seconds())
	for service, store := range e.shards {
		gone := store.evictStale(before)
		gone = append(gone, store.evictToCap(e.cfg.MaxClusters)...)
		if len(gone) == 0 {
			continue
		}
		deleteClusters(ctx, e.db.Pool(), service, gone)
		for _, id := range gone {
			delete(e.templatedAt, fmt.Sprintf("%s:%d", service, id))
		}
	}
}
