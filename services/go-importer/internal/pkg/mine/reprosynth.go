package mine

// Shape -> InteractivePlan synthesis, ported from the reference shape.py
// (analyse_shape + _minimize + _gate + emit_program). analyseShape builds the
// const/var skeleton and per-slot classification from a diverse sample of a
// shape's homogeneous members; emitPlan renders it as the runnable
// InteractivePlan (typed steps + carried-value Links) the replicator consumes,
// or an Unreproducible plan (with a reason) when a required slot is COMPUTED or
// the service is structurally opaque.

import (
	"bytes"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"go-importer/internal/pkg/db"
)

type slotClass struct {
	kind string // FLAGID MIRROR SELFREF RANDOM LENGTH CONST_WS CONST_HDR FLAG_PLANT COMPUTED

	echoTransform string // FLAGID
	external      bool   // FLAGID (external gameserver id)
	slaSelfMirror bool   // FLAGID (also present in prior server -> SLA self-read)

	transform  string // MIRROR
	prefix     []byte // MIRROR
	suffix     []byte // MIRROR
	sourceTurn int    // MIRROR producer client-turn

	srcT int // SELFREF source turn
	srcV int // SELFREF source vk

	charset string // RANDOM
	minLen  int    // RANDOM
	maxLen  int    // RANDOM

	crypto  bool   // COMPUTED
	example []byte // COMPUTED / misc
}

type reproProgram struct {
	ok         bool
	buildFail  string
	structural bool
	gate       []string
	nturns     int
	aligns     []turnAlign
	classes    map[[2]int]*slotClass
	vslotIndex [][2]int
	rti        int
	flag       []byte
	nBuild     int
	required   []int
	repFlow    []db.Turn
	tables0    [][][]byte // representative flow's per-turn slot values
}

var (
	reAuthCtx = regexp.MustCompile(`(?i)(cookie:|authorization:|bearer\s|phpsessid=|session=|sessionid=|token"?\s*[:=]|"sid"|api[_-]?key)`)
	reLenCtx  = regexp.MustCompile(`(?i)content-length:\s*$`)
	reWSFrame = regexp.MustCompile(`\b40\{"|\b0\{"sid"`)
	reRegTurn = regexp.MustCompile(`(?i)/register|/signup|Signup`)
	reMenuInt = regexp.MustCompile(`^\d{1,3}$`)
	// reBenignHdr matches (from the start of a header line up to the slot) a
	// client-preference request header whose value the server does not key
	// anything security-relevant on. Such a value is CLIENT-CHOSEN, so any
	// recorded literal replays validly — it must never gate an otherwise-
	// reproducible exfil as COMPUTED. Deliberately EXCLUDES Host, Content-Type,
	// Content-Length, Cookie and Authorization (those are load-bearing / handled
	// elsewhere), so a body data param, a length, or an auth/crypto value is
	// never masked. Scoped to the header region only (see benignHdrPos).
	reBenignHdr = regexp.MustCompile(`(?i)^(accept|accept-encoding|accept-language|accept-charset|accept-datetime|user-agent|connection|keep-alive|referer|referrer|origin|cache-control|pragma|dnt|te|priority|upgrade-insecure-requests|x-requested-with|sec-[a-z-]+)\s*:`)
)

func isLineProto(service string, port int) bool {
	return port == 1337 || service == "skypedia-line" || service == "vault"
}

func isRegisterTurn(turns []db.Turn, ti int) bool {
	ct := clientTurns(turns)
	if ti >= len(ct) {
		return false
	}
	return reRegTurn.Match(ct[ti])
}

// structuralGate decides TLS-opaque / WS-framed / flag-not-in-cleartext from the
// server bytes alone (no client-turn model needed).
func structuralGate(turns []db.Turn, port int, flagRe *regexp.Regexp) []string {
	var reasons []string
	srv := serverAll(turns)
	if port == 443 || port == 8443 || bytes.HasPrefix(srv, []byte{0x16, 0x03}) {
		reasons = append(reasons, "TLS-opaque")
	}
	if bytes.Contains(srv, []byte("Sec-WebSocket-Accept")) || reWSFrame.Match(srv) {
		reasons = append(reasons, "WS-framed")
	}
	if flag := flagOf(turns, flagRe); flag != nil {
		vis := false
		for _, rep := range flagForms(flag) {
			if bytes.Contains(srv, rep) {
				vis = true
				break
			}
		}
		if !vis {
			reasons = append(reasons, "flag-not-in-cleartext-or-{hex,b64}")
		}
	}
	return reasons
}

// retrievalIndex returns the first client turn whose paired response carries the
// flag (and that response). For line protocols with no wire interleaving it
// falls back to the last non-empty client line + the whole server blob.
func retrievalIndex(turns []db.Turn, flagRe *regexp.Regexp) (int, []byte, bool) {
	resps := responsesPaired(turns)
	ct := clientTurns(turns)
	for i := 0; i < len(ct); i++ {
		if i < len(resps) && flagRe.Match(resps[i]) {
			return i, resps[i], true
		}
	}
	if flag := flagOf(turns, flagRe); flag != nil {
		last := len(ct) - 1
		for last > 0 && len(bytes.TrimSpace(ct[last])) == 0 {
			last--
		}
		if last < 0 {
			last = 0
		}
		return last, serverAll(turns), true
	}
	return 0, nil, false
}

func modeInt(vals []int) int {
	counts := map[int]int{}
	best, bestN := vals[0], 0
	for _, v := range vals {
		counts[v]++
		if counts[v] > bestN || (counts[v] == bestN && v < best) {
			best, bestN = v, counts[v]
		}
	}
	return best
}

// analyseShape builds the const/var skeleton + slot classification from a
// diverse, evenly-spaced sample of the build flows.
func analyseShape(allFlows [][]db.Turn, service string, port int, flagRe *regexp.Regexp) *reproProgram {
	if sg := structuralGate(allFlows[0], port, flagRe); len(sg) > 0 {
		return &reproProgram{ok: true, structural: true, gate: sg,
			classes: map[[2]int]*slotClass{}, flag: flagOf(allFlows[0], flagRe), nBuild: len(allFlows),
			repFlow: allFlows[0]}
	}
	turnCounts := make([]int, len(allFlows))
	for i, f := range allFlows {
		turnCounts[i] = len(clientTurns(f))
	}
	modal := modeInt(turnCounts)
	var pool [][]db.Turn
	for _, f := range allFlows {
		if len(clientTurns(f)) == modal {
			pool = append(pool, f)
		}
	}
	if len(pool) < 2 {
		return &reproProgram{buildFail: "ragged-session (client-turn count varies)"}
	}
	var flows [][]db.Turn
	if len(pool) > reproAlignSample {
		step := float64(len(pool)) / float64(reproAlignSample)
		for i := 0; i < reproAlignSample; i++ {
			flows = append(flows, pool[int(float64(i)*step)])
		}
	} else {
		flows = pool
	}
	nturns := modal
	if nturns == 0 {
		return &reproProgram{buildFail: "no client turns"}
	}

	// 1. ALIGN per client-turn position (token-level).
	aligns := make([]turnAlign, nturns)
	for ti := 0; ti < nturns; ti++ {
		streams := make([][]byte, len(flows))
		for k, f := range flows {
			streams[k] = clientTurns(f)[ti]
		}
		aligns[ti] = alignTurn(streams)
	}
	// 2. slot tables per flow.
	tables := make([][][][]byte, len(flows))
	for k, f := range flows {
		ct := clientTurns(f)
		tbl := make([][][]byte, nturns)
		for ti := 0; ti < nturns; ti++ {
			if ti >= len(ct) {
				return &reproProgram{buildFail: "alignment-extract-failed"}
			}
			vals := extractRunValues(aligns[ti], ct[ti])
			if vals == nil {
				return &reproProgram{buildFail: "alignment-extract-failed"}
			}
			tbl[ti] = vals
		}
		tables[k] = tbl
	}
	// index V-slots as (turn, vseg_ordinal).
	var vslotIndex [][2]int
	for ti := 0; ti < nturns; ti++ {
		for vk := range aligns[ti].vranges {
			vslotIndex = append(vslotIndex, [2]int{ti, vk})
		}
	}
	slotVals := func(ti, vk int) [][]byte {
		out := make([][]byte, len(flows))
		for k := range flows {
			out[k] = tables[k][ti][vk]
		}
		return out
	}

	// retrieval turn + flag response per flow.
	flagResps := make([][]byte, len(flows))
	ris := make([]int, len(flows))
	for k, f := range flows {
		ri, resp, ok := retrievalIndex(f, flagRe)
		if !ok {
			return &reproProgram{buildFail: "flag not located in any server response"}
		}
		ris[k] = ri
		flagResps[k] = resp
	}
	rti := modeInt(ris)

	slotsEqual := func(a, b [2]int) bool {
		va, vb := slotVals(a[0], a[1]), slotVals(b[0], b[1])
		for i := range va {
			if !bytes.Equal(va[i], vb[i]) || len(va[i]) < 4 {
				return false
			}
		}
		return true
	}
	referencedLater := map[[2]int]bool{}
	for idx, s := range vslotIndex {
		for _, s2 := range vslotIndex[idx+1:] {
			if slotsEqual(s, s2) {
				referencedLater[s] = true
				break
			}
		}
	}

	// URL-positioned (in the request line), auth-positioned (Cookie/Authorization
	// value), length-positioned (a Content-Length value).
	urlPos := map[[2]int]bool{}
	authPos := map[[2]int]bool{}
	lenPos := map[[2]int]bool{}
	benignHdrPos := map[[2]int]bool{}
	for ti := 0; ti < nturns; ti++ {
		refb := segBytes(aligns[ti])
		fl := bytes.IndexByte(refb, '\n')
		if fl < 0 {
			fl = len(refb)
		}
		// Header region ends at the blank line before the body; a slot in the body
		// (JSON data param, crypto blob) must NOT be treated as a benign header.
		bodyStart := bytes.Index(refb, []byte("\r\n\r\n"))
		offs := slotOffsets(aligns[ti])
		for vk, off := range offs {
			urlPos[[2]int{ti, vk}] = off < fl
			authWin := refb[maxInt(0, off-40):off]
			authPos[[2]int{ti, vk}] = reAuthCtx.Match(authWin)
			lenWin := refb[maxInt(0, off-24):off]
			lenPos[[2]int{ti, vk}] = reLenCtx.Match(lenWin)
			// Benign iff past the request line, before the body, and its header
			// line starts with an allowlisted client-preference header name.
			if off > fl && (bodyStart < 0 || off <= bodyStart) {
				lineStart := bytes.LastIndexByte(refb[:off], '\n') + 1
				benignHdrPos[[2]int{ti, vk}] = reBenignHdr.Match(refb[lineStart:off])
			}
		}
	}

	flag := flagOf(flows[0], flagRe)
	classes := map[[2]int]*slotClass{}
	for _, sv := range vslotIndex {
		ti, vk := sv[0], sv[1]
		vals := slotVals(ti, vk)
		prior := make([][]byte, len(flows))
		for k, f := range flows {
			prior[k] = priorServer(f, ti)
		}

		// pure whitespace / empty -> framing jitter, copy.
		allWS := true
		for _, v := range vals {
			if len(bytes.TrimSpace(v)) != 0 {
				allWS = false
				break
			}
		}
		if allWS {
			classes[sv] = &slotClass{kind: "CONST_WS"}
			continue
		}
		// BENIGN HTTP request-header value (Accept-Encoding, User-Agent,
		// Connection, ...): client-chosen, not keyed on by the server, so ANY
		// recorded value replays validly. Pin it to the recorded literal (CONST)
		// rather than let its cross-client variation gate the whole session
		// COMPUTED. Checked before FLAGID/MIRROR/RANDOM because benign header
		// tokens ("close", "keep-alive", "br, zstd") otherwise coincidentally
		// co-occur in server bytes and mis-type as FLAGID. Position-scoped (header
		// region, allowlisted name) so a body/auth/length slot is never masked;
		// nop-proof remains the sole arbiter of a real exploit.
		if benignHdrPos[sv] {
			classes[sv] = &slotClass{kind: "CONST_HDR"}
			continue
		}
		// FLAG_PLANT: client is sending the flag itself.
		if allFlag(vals, flagRe) {
			classes[sv] = &slotClass{kind: "FLAG_PLANT"}
			continue
		}
		// FLAGID: value appears in this flow's flag-bearing response (selector/echo).
		fidTf := make([]string, len(vals))
		allFid := true
		for k, v := range vals {
			fidTf[k] = valueIn(v, flagResps[k])
			if fidTf[k] == "" {
				allFid = false
			}
		}
		if allFid && distinctLens(vals) <= 3 && anyDiffer(vals) {
			alsoPrior := true
			for k, v := range vals {
				if valueIn(v, prior[k]) == "" {
					alsoPrior = false
					break
				}
			}
			classes[sv] = &slotClass{kind: "FLAGID", echoTransform: fidTf[0], slaSelfMirror: alsoPrior}
			continue
		}
		// LENGTH: a Content-Length value -> derivable byte length of the body.
		if lenPos[sv] && allDigits(vals) {
			classes[sv] = &slotClass{kind: "LENGTH"}
			continue
		}
		// MIRROR: value comes from a PRIOR server message.
		if mir := discoverMirror(vals, prior); mir != nil {
			srcTurn := mirrorSourceTurn(flows[0], ti, mir.prefix)
			// Re-derive the capture delimiters within the SOURCE TURN's response
			// ALONE. discoverMirror derives them over the whole concatenated prior
			// server, so a suffix can bleed into a LATER turn's response — which in
			// a minimized live single-connection replay (that later turn is often
			// dropped) never arrives, leaving the extract unmatchable. Confining the
			// delimiters to the one response the producer step actually reads keeps
			// the emitted extract runnable; fall back to the original delimiters if
			// the value is not self-contained in that single response.
			srcResps := make([][]byte, len(flows))
			for k, f := range flows {
				rp := responsesPaired(f)
				if srcTurn < len(rp) {
					srcResps[k] = rp[srcTurn]
				}
			}
			m := mir
			if m2 := discoverMirror(vals, srcResps); m2 != nil {
				m = m2
			}
			classes[sv] = &slotClass{kind: "MIRROR", transform: m.transform,
				prefix: m.prefix, suffix: m.suffix, sourceTurn: srcTurn}
			continue
		}
		// FLAGID-EXTERNAL: a non-echoed URL selector in the RETRIEVAL turn.
		if ti == rti && urlPos[sv] && looksIDSelector(vals) && !looksCrypto(vals, prior) {
			classes[sv] = &slotClass{kind: "FLAGID", echoTransform: "none", external: true}
			continue
		}
		// SELFREF: equals an earlier client value.
		if sref, ok := earlierClientSlot(sv, vslotIndex, slotsEqual); ok {
			classes[sv] = &slotClass{kind: "SELFREF", srcT: sref[0], srcV: sref[1]}
			continue
		}
		// A Cookie/Authorization value that was NOT a mirror above is an external
		// session token we cannot regenerate: NEVER treat it as RANDOM.
		if authPos[sv] {
			classes[sv] = &slotClass{kind: "COMPUTED", crypto: false, example: firstN(vals[0], 40)}
			continue
		}
		// RANDOM: client-originated credential/nonce (never crypto-derived).
		lineVal := isLineProto(service, port) && !reMenuInt.Match(bytes.TrimSpace(clientTurns(flows[0])[ti]))
		credCtx := referencedLater[sv] || ti == 0 || isRegisterTurn(flows[0], ti) || lineVal
		if !looksCrypto(vals, prior) {
			if rnd := classifyRandom(vals, credCtx); rnd != nil {
				classes[sv] = &slotClass{kind: "RANDOM", charset: rnd.charset, minLen: rnd.minLen, maxLen: rnd.maxLen}
				continue
			}
		}
		// COMPUTED (crypto challenge/response, unknown data params).
		classes[sv] = &slotClass{kind: "COMPUTED", crypto: looksCrypto(vals, prior), example: firstN(vals[0], 40)}
	}

	prog := &reproProgram{ok: true, nturns: nturns, aligns: aligns, classes: classes,
		vslotIndex: vslotIndex, rti: rti, flag: flag, nBuild: len(flows),
		repFlow: flows[0], tables0: tables[0]}
	// 3. MINIMIZE.
	var flagidVals [][]byte
	for _, sv := range vslotIndex {
		if sv[0] == rti && classes[sv].kind == "FLAGID" {
			flagidVals = append(flagidVals, tables[0][sv[0]][sv[1]])
		}
	}
	prog.required = minimizeTurns(prog, flows[0], flagidVals)
	// 5. GATE.
	prog.gate = finalGate(prog, flows[0], port, flagRe)
	return prog
}

func segBytes(al turnAlign) []byte {
	var b []byte
	for _, s := range al.segs {
		b = append(b, s.data...)
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func allFlag(vals [][]byte, flagRe *regexp.Regexp) bool {
	for _, v := range vals {
		if len(bytes.TrimSpace(v)) == 0 || !flagRe.Match(v) {
			return false
		}
	}
	return true
}

func distinctLens(vals [][]byte) int {
	seen := map[int]struct{}{}
	for _, v := range vals {
		seen[len(v)] = struct{}{}
	}
	return len(seen)
}

func anyDiffer(vals [][]byte) bool {
	for i := 1; i < len(vals); i++ {
		if !bytes.Equal(vals[i-1], vals[i]) {
			return true
		}
	}
	return false
}

func allDigits(vals [][]byte) bool {
	for _, v := range vals {
		if len(v) == 0 {
			return false
		}
		for _, c := range v {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func earlierClientSlot(cur [2]int, vslotIndex [][2]int, equal func(a, b [2]int) bool) ([2]int, bool) {
	for _, s2 := range vslotIndex {
		if s2 == cur {
			break
		}
		if equal(cur, s2) {
			return s2, true
		}
	}
	return [2]int{}, false
}

// mirrorSourceTurn is the earliest client turn whose response first contains the
// mirror source prefix (for minimization).
func mirrorSourceTurn(turns []db.Turn, ti int, prefix []byte) int {
	resps := responsesPaired(turns)
	for i := 0; i < ti; i++ {
		if i < len(resps) && bytes.Contains(resps[i], prefix) {
			return i
		}
	}
	return maxInt(0, ti-1)
}

// minimizeTurns keeps the whole connection prefix through the retrieval turn,
// dropping only a provable SELF-LOOP PLANT: a turn whose response supplies the
// very flagId the retrieval selects, that nothing kept data-depends on.
func minimizeTurns(prog *reproProgram, turns []db.Turn, flagidVals [][]byte) []int {
	required := map[int]bool{}
	for t := 0; t <= prog.rti; t++ {
		required[t] = true
	}
	depTurns := map[int]bool{}
	for _, sv := range prog.vslotIndex {
		c := prog.classes[sv]
		switch c.kind {
		case "MIRROR":
			depTurns[c.sourceTurn] = true
		case "SELFREF":
			depTurns[c.srcT] = true
		}
	}
	resps := responsesPaired(turns)
	for t := 0; t < prog.rti; t++ {
		if depTurns[t] {
			continue
		}
		if t < len(resps) && len(flagidVals) > 0 {
			for _, fv := range flagidVals {
				if len(fv) > 0 && bytes.Contains(resps[t], fv) {
					delete(required, t)
					break
				}
			}
		}
	}
	out := make([]int, 0, len(required))
	for t := range required {
		out = append(out, t)
	}
	sort.Ints(out)
	return out
}

// finalGate reports why a plan is UNREPRODUCIBLE: TLS/WS/opaque, flag not in
// cleartext, or ANY required slot is COMPUTED (crypto challenge/response,
// HMAC/JWT-forge, external session token, unknown data param).
func finalGate(prog *reproProgram, turns []db.Turn, port int, flagRe *regexp.Regexp) []string {
	var reasons []string
	srv := serverAll(turns)
	if port == 443 || port == 8443 || bytes.HasPrefix(srv, []byte{0x16, 0x03}) {
		reasons = append(reasons, "TLS-opaque")
	}
	if bytes.Contains(srv, []byte("Sec-WebSocket-Accept")) || reWSFrame.Match(srv) {
		reasons = append(reasons, "WS-framed")
	}
	if prog.flag != nil {
		vis := false
		for _, rep := range flagForms(prog.flag) {
			if bytes.Contains(srv, rep) {
				vis = true
				break
			}
		}
		if !vis {
			reasons = append(reasons, "flag-not-in-cleartext-or-{hex,b64}")
		}
	} else {
		reasons = append(reasons, "no-flag")
	}
	req := map[int]bool{}
	for _, t := range prog.required {
		req[t] = true
	}
	var computed [][2]int
	for _, sv := range prog.vslotIndex {
		if prog.classes[sv].kind == "COMPUTED" && req[sv[0]] {
			computed = append(computed, sv)
		}
	}
	if len(computed) > 0 {
		show := computed[0]
		kind := "data"
		for _, s := range computed {
			if prog.classes[s].crypto {
				show, kind = s, "crypto"
				break
			}
		}
		reasons = append(reasons, "COMPUTED-required-slot ("+strconv.Itoa(len(computed))+", "+kind+") e.g. "+
			strconv.Quote(string(prog.classes[show].example)))
	}
	return reasons
}

// ---------------------------------------------------------------- emit
// synthesizeInteractivePlan is the top-level shape->plan entry: align + classify
// + minimize + gate the homogeneous members, then emit the runnable plan (or an
// Unreproducible one with a reason). flagRe is the game FLAG matcher.
func synthesizeInteractivePlan(service string, port int, flows [][]db.Turn, flagRe *regexp.Regexp) InteractivePlan {
	prog := analyseShape(flows, service, port, flagRe)
	return emitPlan(prog, service, port)
}

func emitPlan(prog *reproProgram, service string, port int) InteractivePlan {
	plan := InteractivePlan{Service: service, Port: port, Steps: []InteractiveStep{}, Links: []InteractiveLink{}}
	if !prog.ok {
		plan.Unreproducible = true
		plan.Reason = prog.buildFail
		return plan
	}
	if len(prog.gate) > 0 {
		plan.Unreproducible = true
		plan.Reason = strings.Join(prog.gate, "; ")
		return plan
	}
	stepIndex := map[int]int{}
	for si, ti := range prog.required {
		stepIndex[ti] = si
	}
	resps := responsesPaired(prog.repFlow)
	for _, ti := range prog.required {
		al := prog.aligns[ti]
		segs := make([]Segment, 0, len(al.segs))
		slots := make([]Slot, 0, len(al.vranges))
		vk := 0
		for _, s := range al.segs {
			if !s.isVar {
				segs = append(segs, Segment{Const: append([]byte(nil), s.data...)})
				continue
			}
			segs = append(segs, Segment{Var: true})
			c := prog.classes[[2]int{ti, vk}]
			slots = append(slots, emitSlot(prog, ti, vk, c, stepIndex))
			switch c.kind {
			case "MIRROR":
				if psi, ok := stepIndex[c.sourceTurn]; ok {
					plan.Links = append(plan.Links, InteractiveLink{
						Kind: "mirror", ProducerStep: psi, ConsumerStep: stepIndex[ti],
						Extract: mirrorRegex(c.prefix, c.suffix), InjectSlot: vk, Transform: c.transform,
					})
				}
			case "SELFREF":
				if psi, ok := stepIndex[c.srcT]; ok {
					plan.Links = append(plan.Links, InteractiveLink{
						Kind: "selfref", ProducerStep: psi, ProducerSlot: c.srcV,
						ConsumerStep: stepIndex[ti], InjectSlot: vk,
					})
				}
			}
			vk++
		}
		var expect *string
		if ti < len(resps) {
			expect = promptMarker(resps[ti])
		}
		plan.Steps = append(plan.Steps, InteractiveStep{
			Template: Template{Segments: segs, Slots: slots}, Expect: expect})
	}
	return plan
}

func emitSlot(prog *reproProgram, ti, vk int, c *slotClass, stepIndex map[int]int) Slot {
	var example []byte
	if ti < len(prog.tables0) && vk < len(prog.tables0[ti]) {
		example = prog.tables0[ti][vk]
	}
	switch c.kind {
	case "FLAGID":
		return Slot{Type: SlotFlagID}
	case "MIRROR":
		s := Slot{Type: SlotMirror, Transform: c.transform,
			MirrorPrefix: append([]byte(nil), c.prefix...), MirrorSuffix: append([]byte(nil), c.suffix...)}
		if psi, ok := stepIndex[c.sourceTurn]; ok {
			s.SourceStep = psi
		}
		return s
	case "SELFREF":
		s := Slot{Type: SlotSelfref, SourceSlot: c.srcV}
		if psi, ok := stepIndex[c.srcT]; ok {
			s.SourceStep = psi
		}
		return s
	case "RANDOM":
		s := Slot{Type: SlotRandom, MinLen: c.minLen, MaxLen: c.maxLen}
		if len(example) > 0 {
			s.Charclass = DetectCharclass(bytes.TrimSpace(example)).String()
			if utf8.Valid(example) {
				s.Example = string(example)
			}
		}
		return s
	case "LENGTH":
		return Slot{Type: SlotLength}
	case "CONST_WS", "CONST_HDR":
		if utf8.Valid(example) {
			return Slot{Type: SlotConst, Example: string(example)}
		}
		return Slot{Type: SlotConst}
	case "FLAG_PLANT":
		return Slot{Type: SlotFlag}
	default: // COMPUTED — only reachable in a plan we do not actually emit steps for
		s := Slot{Type: SlotComputed}
		if utf8.Valid(example) {
			s.Example = string(example)
		}
		return s
	}
}

// mirrorRegex builds the replicator extract pattern: prefix (capture) suffix,
// DOTALL so a source spanning newlines still captures. Capture group 1 is the
// server representation of the mirrored value.
func mirrorRegex(prefix, suffix []byte) string {
	var b strings.Builder
	b.WriteString("(?s)")
	b.WriteString(regexp.QuoteMeta(string(prefix)))
	if len(suffix) > 0 {
		b.WriteString("(.*?)")
		b.WriteString(regexp.QuoteMeta(string(suffix)))
	} else {
		b.WriteString("(.*)")
	}
	return b.String()
}

// promptMarker mirrors pendingPrompt on an already-collected response: the text
// after the last newline, trailing spaces + NULs stripped; nil when empty.
func promptMarker(data []byte) *string {
	if idx := bytes.LastIndexByte(data, '\n'); idx >= 0 {
		data = data[idx+1:]
	}
	prompt := strings.ReplaceAll(strings.TrimRight(string(data), " "), "\x00", "")
	if prompt == "" {
		return nil
	}
	return &prompt
}
