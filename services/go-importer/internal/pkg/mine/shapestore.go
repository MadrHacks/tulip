package mine

import (
	"encoding/json"
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
}

// NewShapeStore builds an empty store; a non-positive cap falls back to the
// default per-service shape cap.
func NewShapeStore(maxShapes int) *ShapeStore {
	if maxShapes <= 0 {
		maxShapes = defaultMaxShapes
	}
	return &ShapeStore{shards: map[string]*shapeShard{}, maxShapes: maxShapes}
}

func (ss *ShapeStore) shard(service string) *shapeShard {
	sh := ss.shards[service]
	if sh == nil {
		sh = newShapeShard()
		ss.shards[service] = sh
	}
	return sh
}

// ObserveResult is what Observe hands back so the caller (later wired into
// handle()) can tag the flow: the per-unit shape ids in flow order and the
// flow's session shape signature (the ordered id sequence).
type ObserveResult struct {
	ShapeIDs     []int
	SessionShape string
}

// Observe folds one flow's segmented request units into their service shard. For
// each unit it runs skeleton -> Drain -> shape id, updates that shape's members
// and aggregated signal vector, and records the flow's session shape. feats must
// be paired 1:1 with units (feats[i] is unit i's response signal vector);
// flagIn is the flow-level flag_in signal, carried onto every unit's shape. t is
// the flow time, recorded for eviction. Actors (User-Agent) are read per unit
// from the skeleton pass, never a clustering token.
func (ss *ShapeStore) Observe(service string, units []RequestUnit, feats []RespFeatures, flagIn bool, t int64) ObserveResult {
	sh := ss.shard(service)
	ids := make([]int, 0, len(units))
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
		// Keep a bounded reservoir of the RAW unit bytes (not the skeleton) for
		// replay-template synthesis. Members was just incremented above, so it is
		// the running member count used for the deterministic reservoir slot.
		st.observeSample(u.Client)
		ids = append(ids, id)
	}

	sig := SessionShape(ids)
	sh.sessions[sig]++
	return ObserveResult{ShapeIDs: ids, SessionShape: sig}
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
	TemplateBody  []byte // marshaled *Template (replay template), or nil
}

// snapshot returns every shard's shapes as durable snapshots, keyed by service.
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
				FlagPresent:   st.shape.Signals.FlagPresent,
				FlagIn:        st.shape.Signals.FlagIn,
				Actors:        copyActors(st.shape.Signals.Actors),
				FirstSeen:     st.firstSeen,
				LastSeen:      st.lastSeen,
				TemplateBody:  st.templateBody(),
			})
		}
		out[svc] = snaps
	}
	return out
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
