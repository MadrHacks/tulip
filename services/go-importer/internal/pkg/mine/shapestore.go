package mine

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// ShapeStore is the STREAMING home for request-unit shapes, one Drain miner per
// service shard (shapes never cross services). It is the online counterpart of
// the pure stage-4/5 grouping views (shape.go): where GroupShapes aggregates a
// batch, ShapeStore folds flows in one at a time and keeps stable shape ids and
// aggregated signals across the whole run, snapshotting them so a minecore
// restart continues the same ids.
//
// DESIGN PRINCIPLE (locked, see shape.go): a shape is NEUTRAL. It carries an
// observable SIGNAL VECTOR only (flag_present count, flag_in, actors, size) and
// no "attack" field. flag_present is a SIGNAL, never a verdict.
//
// Bounded memory: each shard is capped at maxShapes; EvictToCap drops the
// least-recently-seen shapes at the STORE level. This is NOT drain3's
// max_clusters LRU (which silently evicts mid-match and corrupts templates) —
// the Drain stays uncapped and correct; the cap lives on the derived shapes.

const defaultMaxShapes = 4096 // per-service shape cap

// Per-shape replay-template substrate. Each shape keeps a small bounded
// reservoir of RAW request-unit byte samples so its replay template can be
// synthesized by multiple-alignment (align.go) without a DB re-fetch — the
// streaming counterpart of the cluster path, which re-reads member bytes from
// Timescale. Only a handful of (size-capped) samples live per shape, so the
// memory stays bounded: <= shapeReservoirCap * shapeSampleCap per shape.
const (
	shapeReservoirCap = 8               // raw-unit samples kept per shape for alignment
	maxFeatureBytes   = 8192            // 8 KB captures a request's shape (a bounded per-sample cap)
	shapeSampleCap    = maxFeatureBytes // truncate each stored sample (8 KB captures a request's shape)
)

// shapeState is a live shape: the neutral Shape plus streaming bookkeeping
// (seen times, the alignment reservoir, and the synthesized replay template)
// the pure Shape deliberately omits.
type shapeState struct {
	shape     Shape
	firstSeen int64
	lastSeen  int64
	// samples is the bounded reservoir of raw request-unit bytes (<= cap),
	// reservoir-sampled as Observe sees members. NOT the skeleton — the raw
	// bytes, so synthesis can align on the real (canonical) request and recover
	// its variable slots. Not persisted; re-accumulates at runtime after a restart.
	samples [][]byte
	// template is the synthesized REPLAY template (aligned Const/Var segments +
	// typed slots), nil until the shape reaches quorum. Persisted as the
	// template_body jsonb column so it survives a restart until re-synthesized.
	template *Template
	// ports is the histogram of member destination ports (port -> member count).
	// A shape is per-service and a service almost always lives on one port, so
	// this is near-degenerate; its mode is the shape's representative REPLAY port.
	// Only the mode is persisted (mine.shape.port); on restore the histogram is
	// re-seeded from it so the representative stays stable across a restart.
	ports map[int]int
	// variants is the CARDINALITY-REFINEMENT reservoir: distinct member skeleton
	// -> aggregated signals. It records the literal each <*> position took so the
	// refinement (refine.go) can tell a structural position (low-card) from a value
	// position (high-card) and un-merge the former. Bounded at splitVariantCap
	// distinct skeletons; on overflow it is freed and overflowed is set (a high-
	// card value dominates, so the shape stays merged). Not persisted — it re-
	// accumulates from live traffic after a restart, like the sample reservoir.
	variants   map[string]*variantAgg
	overflowed bool
}

// repPort is the shape's representative destination port: the most-common member
// port (its mode), with a deterministic (smallest-port) tie-break so the choice
// is stable regardless of map iteration order. 0 when no port was ever recorded.
func (st *shapeState) repPort() int {
	best, bestN := 0, -1
	for p, n := range st.ports {
		if n > bestN || (n == bestN && p < best) {
			best, bestN = p, n
		}
	}
	return best
}

// observePort folds one member's destination port into the shape's histogram.
func (st *shapeState) observePort(port int) {
	if st.ports == nil {
		st.ports = map[int]int{}
	}
	st.ports[port]++
}

// observeSample folds one raw request-unit sample into the shape's bounded
// reservoir, mirroring clusterStore.addMember's deterministic (randomness-free)
// reservoir: append until full, then overwrite a slot chosen by the member
// count. Each sample is size-capped and copied so the reservoir never aliases or
// retains large payloads. Members must already be incremented for this member.
func (st *shapeState) observeSample(raw []byte) {
	if len(raw) > shapeSampleCap {
		raw = raw[:shapeSampleCap]
	}
	cp := append([]byte(nil), raw...)
	if len(st.samples) < shapeReservoirCap {
		st.samples = append(st.samples, cp)
		return
	}
	st.samples[st.shape.Members%shapeReservoirCap] = cp
}

// shapeShard is one service's streaming shape state: a Drain miner, the shapes
// it derived (keyed by the Drain template id = shape id), and a per-flow session
// signature tally (an in-memory view, not persisted — session ids are just
// sequences of the persisted shape ids and rebuild for free).
type shapeShard struct {
	drain    *Drain
	shapes   map[int]*shapeState
	sessions map[string]int
}

func newShapeShard() *shapeShard {
	return &shapeShard{
		drain:    NewShapeGrouper(),
		shapes:   map[int]*shapeState{},
		sessions: map[string]int{},
	}
}

// ShapeStore holds one shapeShard per service.
type ShapeStore struct {
	shards    map[string]*shapeShard
	maxShapes int
	// splitCard is the cardinality knob for refinement (refine.go): a <*> position
	// with <= splitCard distinct literals is STRUCTURAL and gets un-merged; more is
	// a VALUE and stays wildcarded. splitVariantCap bounds the per-shape variant
	// reservoir. Both default (defaultSplitCard / defaultSplitVariantCap) and are
	// overridable via SetSplitParams (env: MINECORE_SPLIT_CARD / _SPLIT_VARIANTS).
	splitCard       int
	splitVariantCap int
}

// NewShapeStore builds an empty store; a non-positive cap falls back to the
// default per-service shape cap. Refinement knobs default and can be overridden
// with SetSplitParams.
func NewShapeStore(maxShapes int) *ShapeStore {
	if maxShapes <= 0 {
		maxShapes = defaultMaxShapes
	}
	return &ShapeStore{
		shards:          map[string]*shapeShard{},
		maxShapes:       maxShapes,
		splitCard:       defaultSplitCard,
		splitVariantCap: defaultSplitVariantCap,
	}
}

// SetSplitParams overrides the cardinality-refinement knobs: splitCard (the
// low/high cardinality boundary at a <*> position) and variantCap (the per-shape
// distinct-skeleton reservoir bound). Non-positive values keep the current
// setting, so callers can override one without disturbing the other.
func (ss *ShapeStore) SetSplitParams(splitCard, variantCap int) {
	if splitCard > 0 {
		ss.splitCard = splitCard
	}
	if variantCap > 0 {
		ss.splitVariantCap = variantCap
	}
}

func (ss *ShapeStore) shard(service string) *shapeShard {
	sh := ss.shards[service]
	if sh == nil {
		sh = newShapeShard()
		ss.shards[service] = sh
	}
	return sh
}

// ObserveResult is what Observe hands back so the caller (wired into handle())
// can tag the flow: the per-unit Drain (parent) shape ids in flow order, the
// per-unit CRISP refined shape ids (the granularity the live tags/candidates run
// at), and the flow's session shape signature (the ordered parent-id sequence).
type ObserveResult struct {
	ShapeIDs     []int
	RefinedIDs   []int64
	SessionShape string
}

// Observe folds one flow's segmented request units into their service shard. For
// each unit it runs skeleton -> Drain -> shape id, updates that shape's members
// and aggregated signal vector, and records the flow's session shape. feats must
// be paired 1:1 with units (feats[i] is unit i's response signal vector);
// flagIn is the flow-level flag_in signal, carried onto every unit's shape. port
// is the flow's destination port, folded into each touched shape's port histogram
// so the shape can report a representative REPLAY port. t is the flow time,
// recorded for eviction. Actors (User-Agent) are read per unit from the skeleton
// pass, never a clustering token.
func (ss *ShapeStore) Observe(service string, units []RequestUnit, feats []RespFeatures, flagIn bool, port int, t int64) ObserveResult {
	sh := ss.shard(service)
	ids := make([]int, 0, len(units))
	skels := make([]string, 0, len(units))
	for i, u := range units {
		skeleton, ua := NormalizeUnit(u)
		id := sh.drain.Add(skeleton)

		var f RespFeatures
		if i < len(feats) {
			f = feats[i]
		}

		st := sh.shapes[id]
		if st == nil {
			st = &shapeState{
				shape:     Shape{TemplateID: id, Signals: ShapeSignals{Actors: map[string]int{}}},
				firstSeen: t,
				lastSeen:  t,
				ports:     map[int]int{},
			}
			sh.shapes[id] = st
		}
		// Refresh the template: Drain may have generalized a token to <*> as it
		// saw this member.
		st.shape.Template = sh.drain.Template(id)
		st.shape.Members++
		st.shape.Signals.SizeBucketSum += f.ContentLengthBucket
		if f.FlagPresent {
			st.shape.Signals.FlagPresent++
		}
		if flagIn {
			st.shape.Signals.FlagIn++
		}
		if ua != "" {
			st.shape.Signals.Actors[ua]++
		}
		if t > st.lastSeen {
			st.lastSeen = t
		}
		if t < st.firstSeen {
			st.firstSeen = t
		}
		st.observePort(port)
		// Keep a bounded reservoir of the RAW unit bytes (not the skeleton) for
		// replay-template synthesis. Members was just incremented above, so it is
		// the running member count used for the deterministic reservoir slot.
		st.observeSample(u.Client)
		// Fold the member's skeleton + signals (and raw bytes) into the cardinality-
		// refinement reservoir so refine.go can recover each <*> position's literal
		// alphabet and align a crisp per-sub-shape replay template.
		st.observeVariant(skeleton, f, flagIn, ua, u.Client, ss.splitVariantCap)
		ids = append(ids, id)
		skels = append(skels, skeleton)
	}

	// Resolve each unit's CRISP refined id now that this flow's members are folded
	// into the reservoir. Memoized per parent shape (a flow often repeats one
	// interaction), the id is the granularity handle() tags the flow at.
	refined := make([]int64, len(ids))
	cache := map[int][]RefinedShape{}
	for i := range ids {
		refined[i] = sh.refinedIDFor(ids[i], skels[i], ss.splitCard, cache)
	}

	sig := SessionShape(ids)
	sh.sessions[sig]++
	return ObserveResult{ShapeIDs: ids, RefinedIDs: refined, SessionShape: sig}
}

// Shapes returns a snapshot copy of one service's live shapes, ordered by shape
// id, for read-only consumers (persistence, cockpit). Actor maps are copied so
// callers cannot mutate live state.
func (ss *ShapeStore) Shapes(service string) []Shape {
	sh := ss.shards[service]
	if sh == nil {
		return nil
	}
	out := make([]Shape, 0, len(sh.shapes))
	for _, st := range sh.shapes {
		s := st.shape
		s.Signals.Actors = copyActors(st.shape.Signals.Actors)
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TemplateID < out[j].TemplateID })
	return out
}

// FlagShape identifies a shape carrying the flag_present SIGNAL, with its
// representative replay port — the neutral unit the detection pass pursues.
// flag_present is a SIGNAL (these responses leaked a flag), NEVER a verdict; the
// replicator's NOP-proof remains the sole arbiter of a real exploit.
type FlagShape struct {
	ID   int
	Port int
}

// FlagShapes returns a service shard's shapes whose flag_present signal is > 0,
// each paired with its representative destination port, ordered by shape id. It
// is the neutral shape-side twin of iterating clusters with flagOut > 0 in the
// detection pass.
func (ss *ShapeStore) FlagShapes(service string) []FlagShape {
	sh := ss.shards[service]
	if sh == nil {
		return nil
	}
	out := make([]FlagShape, 0, len(sh.shapes))
	for id, st := range sh.shapes {
		if st.shape.Signals.FlagPresent > 0 {
			out = append(out, FlagShape{ID: id, Port: st.repPort()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RefinedFlagShape is a CRISP flag-leaking shape: a refined sub-shape carrying the
// flag_present SIGNAL, with its representative replay port. It is the granularity
// the detection pass now pursues — one candidate per real interaction-kind, so the
// boomerang IDOR is a distinct target from a byte-adjacent benign endpoint. Still
// NEUTRAL: flag_present is a signal, and the replicator's NOP-proof is the sole
// arbiter of a real exploit.
type RefinedFlagShape struct {
	ID   int64
	Port int
}

// RefinedFlagShapes returns a service shard's CRISP shapes whose flag_present
// signal is > 0, each with its representative destination port, ordered by id. It
// is the refined twin of FlagShapes: it refines every parent shape and reports the
// flag-carrying sub-shapes, so an over-merged parent no longer smears a real
// vector across benign siblings.
func (ss *ShapeStore) RefinedFlagShapes(service string) []RefinedFlagShape {
	sh := ss.shards[service]
	if sh == nil {
		return nil
	}
	seen := map[int64]int{} // refined id -> index in out (merge same-template across parents)
	var out []RefinedFlagShape
	for _, st := range sh.shapes {
		port := st.repPort()
		for _, r := range st.refine(ss.splitCard) {
			if r.Signals.FlagPresent <= 0 {
				continue
			}
			id := refinedShapeIDForTemplate(r.Template)
			if idx, ok := seen[id]; ok {
				if out[idx].Port == 0 {
					out[idx].Port = port
				}
				continue
			}
			seen[id] = len(out)
			out = append(out, RefinedFlagShape{ID: id, Port: port})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Services returns the names of every service shard currently in the store,
// sorted, so callers (e.g. the detection service-name sanity check) can compare
// the mined services against the scoreboard's names.
func (ss *ShapeStore) Services() []string {
	out := make([]string, 0, len(ss.shards))
	for svc := range ss.shards {
		out = append(out, svc)
	}
	sort.Strings(out)
	return out
}

// ShapeCount reports the number of live shapes in a service shard.
func (ss *ShapeStore) ShapeCount(service string) int {
	sh := ss.shards[service]
	if sh == nil {
		return 0
	}
	return len(sh.shapes)
}

// EvictToCap enforces the per-service shape cap by dropping the least-recently-
// seen shapes until at most maxShapes remain in each shard. Evicted shapes are
// removed from both the shape map and the Drain's live template set (freeing the
// heavy state); the Drain counter is left monotonic so an evicted id is never
// reused. Returns the evicted ids per service so the caller can delete their
// persisted rows.
func (ss *ShapeStore) EvictToCap() map[string][]int {
	gone := map[string][]int{}
	for svc, sh := range ss.shards {
		if len(sh.shapes) <= ss.maxShapes {
			continue
		}
		ids := make([]int, 0, len(sh.shapes))
		for id := range sh.shapes {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool {
			a, b := sh.shapes[ids[i]], sh.shapes[ids[j]]
			if a.lastSeen != b.lastSeen {
				return a.lastSeen < b.lastSeen
			}
			return ids[i] < ids[j] // deterministic tie-break
		})
		evict := ids[:len(sh.shapes)-ss.maxShapes]
		for _, id := range evict {
			delete(sh.shapes, id)
			sh.drain.forget(id)
		}
		gone[svc] = evict
	}
	return gone
}

// shapeSnapshot is a shape's durable form: the Drain template (which also re-
// seeds the miner's prefix tree on restore, so shape ids stay stable) plus the
// aggregated signal vector, seen times, and the synthesized replay template
// (TemplateBody: the {segments,slots} json, nil until the shape reaches quorum).
type shapeSnapshot struct {
	ShapeID       int
	Template      string
	Members       int
	SizeBucketSum int
	FlagPresent   int
	FlagIn        int
	Actors        map[string]int
	FirstSeen     int64
	LastSeen      int64
	Port          int    // representative (most-common) member destination port
	TemplateBody  []byte // marshaled *Template (replay template), or nil
}

// snapshot returns every shard's shapes as durable PARENT-SEED snapshots, keyed by
// service. These rows exist to re-seed the Drain (their id + template rebuild the
// prefix tree so parent ids stay stable across a restart) and carry NO flag/replay
// signal: the flag_present SIGNAL and the replay body live on the CRISP refined
// rows (refinedSnapshots), so an over-merged parent never masquerades as a
// candidate. Members is kept (the Drain cluster size for reinsert); actors/size
// ride along as harmless continuity annotations.
func (ss *ShapeStore) snapshot() map[string][]shapeSnapshot {
	out := make(map[string][]shapeSnapshot, len(ss.shards))
	for svc, sh := range ss.shards {
		snaps := make([]shapeSnapshot, 0, len(sh.shapes))
		for id, st := range sh.shapes {
			snaps = append(snaps, shapeSnapshot{
				ShapeID:       id,
				Template:      st.shape.Template,
				Members:       st.shape.Members,
				SizeBucketSum: st.shape.Signals.SizeBucketSum,
				FlagPresent:   0, // seed row: the flag signal lives on the crisp refined rows
				FlagIn:        0,
				Actors:        copyActors(st.shape.Signals.Actors),
				FirstSeen:     st.firstSeen,
				LastSeen:      st.lastSeen,
				Port:          st.repPort(),
				// In production the engine never synthesizes parent templates, so this
				// is nil (the replay body lives on the crisp refined rows). It is kept
				// as st.templateBody() only so the in-memory synth/round-trip machinery
				// stays exercised; a body here is harmless as the candidate gate is
				// flag_present > 0, which a seed row never carries.
				TemplateBody: st.templateBody(),
			})
		}
		out[svc] = snaps
	}
	return out
}

// refinedAgg accumulates one crisp refined shape across every parent that refines
// to its template (a rare cross-parent merge, but kept exact): summed signals, a
// bounded sample union for alignment, and a port histogram for the replay port.
type refinedAgg struct {
	template      string
	members       int
	flagPresent   int
	flagIn        int
	sizeBucketSum int
	actors        map[string]int
	samples       [][]byte
	firstSeen     int64
	lastSeen      int64
	ports         map[int]int
}

// refinedSnapshots is the CRISP durable form of the store: it refines every parent
// shape and emits ONE snapshot per refined interaction-kind (keyed by the stable
// refined id), synthesizing each sub-shape's replay template from its own
// homogeneous samples. These rows are what the candidate reader consumes, so a
// candidate is a crisp vector, not an over-merged parent. It never re-seeds the
// Drain (parent rows do that), so it carries no Drain-stability burden.
func (ss *ShapeStore) refinedSnapshots(flagRe *regexp.Regexp, flagIDs map[string]bool) map[string][]shapeSnapshot {
	out := make(map[string][]shapeSnapshot, len(ss.shards))
	for svc, sh := range ss.shards {
		aggs := map[int64]*refinedAgg{}
		order := make([]int64, 0, len(sh.shapes))
		for _, st := range sh.shapes {
			port := st.repPort()
			for _, r := range st.refine(ss.splitCard) {
				id := refinedShapeIDForTemplate(r.Template)
				a := aggs[id]
				if a == nil {
					a = &refinedAgg{
						template:  r.Template,
						actors:    map[string]int{},
						ports:     map[int]int{},
						firstSeen: st.firstSeen,
						lastSeen:  st.lastSeen,
					}
					aggs[id] = a
					order = append(order, id)
				}
				a.members += r.Members
				a.flagPresent += r.Signals.FlagPresent
				a.flagIn += r.Signals.FlagIn
				a.sizeBucketSum += r.Signals.SizeBucketSum
				for k, v := range r.Signals.Actors {
					a.actors[k] += v
				}
				for _, s := range r.samples {
					if len(a.samples) < refinedGatherCap {
						a.samples = append(a.samples, s)
					}
				}
				if port != 0 {
					a.ports[port] += r.Members
				}
				if st.firstSeen < a.firstSeen {
					a.firstSeen = st.firstSeen
				}
				if st.lastSeen > a.lastSeen {
					a.lastSeen = st.lastSeen
				}
			}
		}
		sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
		snaps := make([]shapeSnapshot, 0, len(order))
		for _, id := range order {
			a := aggs[id]
			var body []byte
			if tpl := synthesizeShapeTemplate(a.samples, flagRe, flagIDs); tpl != nil {
				if b, err := json.Marshal(tpl); err == nil {
					body = b
				}
			}
			snaps = append(snaps, shapeSnapshot{
				ShapeID:       int(id),
				Template:      a.template,
				Members:       a.members,
				SizeBucketSum: a.sizeBucketSum,
				FlagPresent:   a.flagPresent,
				FlagIn:        a.flagIn,
				Actors:        a.actors,
				FirstSeen:     a.firstSeen,
				LastSeen:      a.lastSeen,
				Port:          modePort(a.ports),
				TemplateBody:  body,
			})
		}
		out[svc] = snaps
	}
	return out
}

// modePort returns the most-common port in a histogram (smallest-port tie-break),
// or 0 when empty — the refined shape's representative replay port.
func modePort(ports map[int]int) int {
	best, bestN := 0, -1
	for p, n := range ports {
		if n > bestN || (n == bestN && p < best) {
			best, bestN = p, n
		}
	}
	return best
}

// restoreShapeStore rebuilds a store from persisted snapshots. Rebuilding each
// shard's Drain from the persisted templates (deterministically, in id order)
// re-seeds the prefix tree and counter so the same skeleton maps to the same
// shape id as before the restart — mirroring restoreClusterStore.
func restoreShapeStore(snaps map[string][]shapeSnapshot, maxShapes int) *ShapeStore {
	ss := NewShapeStore(maxShapes)
	for svc, list := range snaps {
		sh := ss.shard(svc)
		ordered := append([]shapeSnapshot(nil), list...)
		sort.Slice(ordered, func(i, j int) bool { return ordered[i].ShapeID < ordered[j].ShapeID })
		for _, s := range ordered {
			// Only Drain-seed parent rows (small ids) rebuild the miner + parent
			// shape state; crisp refined rows (id >= refinedIDBase) re-derive from the
			// variant reservoir as live traffic re-accumulates, so they are skipped
			// here (and left in the DB as candidates until the next refined snapshot).
			if s.ShapeID >= refinedIDBase {
				continue
			}
			sh.drain.reinsert(s.ShapeID, strings.Fields(s.Template), s.Members)
			st := &shapeState{
				shape: Shape{
					TemplateID: s.ShapeID,
					Template:   s.Template,
					Members:    s.Members,
					Signals: ShapeSignals{
						FlagPresent:   s.FlagPresent,
						FlagIn:        s.FlagIn,
						SizeBucketSum: s.SizeBucketSum,
						Actors:        copyActors(s.Actors),
					},
				},
				firstSeen: s.FirstSeen,
				lastSeen:  s.LastSeen,
				ports:     map[int]int{},
			}
			// Re-seed the port histogram from the persisted representative port,
			// weighted by the member count, so the mode stays stable across a
			// restart until new traffic on a different port outweighs it.
			if s.Port != 0 {
				weight := s.Members
				if weight < 1 {
					weight = 1
				}
				st.ports[s.Port] = weight
			}
			// Reload the persisted replay template so it is available before the
			// reservoir re-accumulates and re-synthesizes it (samples themselves
			// are not persisted).
			if len(s.TemplateBody) > 0 {
				var tpl Template
				if err := json.Unmarshal(s.TemplateBody, &tpl); err == nil {
					st.template = &tpl
				}
			}
			sh.shapes[s.ShapeID] = st
		}
	}
	return ss
}

func copyActors(m map[string]int) map[string]int {
	if len(m) == 0 {
		return map[string]int{}
	}
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
