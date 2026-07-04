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
	// retrieval turn + flag response per flow. Derived before the sub-slot
	// refinement so the carve pass can test each slot value against its flow's
	// flag-bearing response (an embedded flagId source).
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

	// 2b. SUB-SLOT REFINEMENT. The token aligner types each variable segment as a
	// WHOLE unit, so a dependency carried by a SUBSTRING (a flagId embedded in a
	// larger field, a server token the aligner split around a const) is dropped.
	// Two structural passes rewrite each turn's alignment + slot table BEFORE
	// classification, so the ordinary classifier then types every refined piece:
	//   - maximalMirrorMerge coalesces a server-issued value split around a const
	//     into ONE maximal contiguous-mirror slot.
	//   - subCarve splits a slot embedding a flagId / prior-server / earlier-client
	//     reference into ordered const + typed sub-slots.
	// Turns are refined in order so a carve's earlier-client references see the
	// already-refined prior turns.
	for ti := 0; ti < nturns; ti++ {
		priors := make([][]byte, len(flows))
		for k, f := range flows {
			priors[k] = priorServer(f, ti)
		}
		earlier := make([][][]byte, len(flows))
		for k := range flows {
			for tj := 0; tj < ti; tj++ {
				earlier[k] = append(earlier[k], tables[k][tj]...)
			}
		}
		refineTurn(aligns, tables, ti, flagResps, priors, earlier)
	}

	// index V-slots as (turn, vseg_ordinal) over the REFINED alignment.
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
	danglingEsc := map[[2]int]bool{}
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
			// A slot whose preceding const bytes end in an ODD run of backslashes
			// abuts a broken JSON escape ("\uXXXX" / "\\" mis-segmented as a lone
			// "\"). Regenerating such a slot would emit invalid JSON (400); flag it
			// so RANDOM is demoted to the recorded literal, keeping the escape faithful.
			danglingEsc[[2]int{ti, vk}] = trailingBackslashesOdd(refb[:off])
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
				// Fix: a RANDOM slot immediately following a dangling JSON backslash
				// escape must NOT be regenerated (it would break the escape and 400).
				// Pin it to the recorded literal so the escape is preserved faithfully.
				if danglingEsc[sv] {
					classes[sv] = &slotClass{kind: "CONST_HDR", example: vals[0]}
					continue
				}
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

// ---------------------------------------------------------------- sub-slot refinement
// The token aligner produces one variable segment per aligned run, typed as a
// WHOLE unit. That drops any dependency carried by a SUBSTRING: a flagId embedded
// in a bigger field (register full_name = random + \x01 + victim flagId), or a
// server-issued token the aligner split around a const. The refinement passes
// below rewrite ONE turn's alignment + per-flow slot table as an ordered []piece
// (structural only), then hand it back so the ORDINARY classifier types every
// refined piece. No new replay primitive: a carved FLAGID/MIRROR/SELFREF sub-slot
// is an ordinary typed slot, and a carved-out constant is an ordinary const segment.

const (
	carveFlagIDMin  = 8 // a carved flagId sub-span must be at least this long
	carveSelfrefMin = 6 // a carved earlier-client (selfref) sub-span minimum
)

// piece is one element of a turn's refined template: a constant literal shared by
// every flow (cb), or a variable sub-slot with its per-flow values (vv).
type piece struct {
	isVar bool
	cb    []byte   // constant bytes (isVar == false)
	vv    [][]byte // per-flow values (isVar == true)
}

// turnToPieces renders a turn's current alignment + per-flow slot values as an
// ordered piece list (const segments interleaved with variable slots).
func turnToPieces(al turnAlign, turnVals [][][]byte) []piece {
	var pieces []piece
	vk := 0
	for _, s := range al.segs {
		if !s.isVar {
			pieces = append(pieces, piece{cb: append([]byte(nil), s.data...)})
			continue
		}
		vv := make([][]byte, len(turnVals))
		for k := range turnVals {
			vv[k] = turnVals[k][vk]
		}
		pieces = append(pieces, piece{isVar: true, vv: vv})
		vk++
	}
	return pieces
}

// piecesToTurn converts a refined piece list back into a turnAlign (adjacent const
// pieces coalesced so the skeleton stays canonical) and the matching per-flow slot
// table. The var segments' data is the representative (flow-0) value so segBytes /
// slotOffsets reconstruct flow 0's exact turn bytes.
func piecesToTurn(pieces []piece, nFlows int) (turnAlign, [][][]byte) {
	var merged []piece
	for _, p := range pieces {
		if !p.isVar && len(merged) > 0 && !merged[len(merged)-1].isVar {
			merged[len(merged)-1].cb = append(merged[len(merged)-1].cb, p.cb...)
			continue
		}
		merged = append(merged, p)
	}
	segs := make([]alignSeg, 0, len(merged))
	var vranges [][2]int
	turnVals := make([][][]byte, nFlows)
	for _, p := range merged {
		if !p.isVar {
			segs = append(segs, alignSeg{data: append([]byte(nil), p.cb...)})
			continue
		}
		var rep []byte
		if len(p.vv) > 0 {
			rep = append([]byte(nil), p.vv[0]...)
		}
		segs = append(segs, alignSeg{isVar: true, data: rep})
		vranges = append(vranges, [2]int{len(segs) - 1, len(segs)})
		for k := 0; k < nFlows; k++ {
			turnVals[k] = append(turnVals[k], p.vv[k])
		}
	}
	return turnAlign{segs: segs, vranges: vranges}, turnVals
}

// refineTurn rewrites turn ti in place: maximal-mirror merge, then sub-carve.
func refineTurn(aligns []turnAlign, tables [][][][]byte, ti int, flagResps, priors [][]byte, earlier [][][]byte) {
	nF := len(tables)
	turnVals := make([][][]byte, nF)
	for k := range tables {
		turnVals[k] = tables[k][ti]
	}
	pieces := turnToPieces(aligns[ti], turnVals)
	pieces = maximalMirrorMerge(pieces, priors)
	pieces = subCarve(pieces, flagResps, priors, earlier)
	al, newVals := piecesToTurn(pieces, nF)
	aligns[ti] = al
	for k := range tables {
		tables[k][ti] = newVals[k]
	}
}

// concatRange returns, per flow, the concatenation of pieces[lo:hi].
func concatRange(pieces []piece, lo, hi, nFlows int) [][]byte {
	out := make([][]byte, nFlows)
	for i := lo; i < hi; i++ {
		p := pieces[i]
		for k := 0; k < nFlows; k++ {
			if p.isVar {
				out[k] = append(out[k], p.vv[k]...)
			} else {
				out[k] = append(out[k], p.cb...)
			}
		}
	}
	return out
}

// allInPriorContig reports that every flow's value is a >=reproMinMirror
// contiguous substring of that flow's prior server bytes.
func allInPriorContig(vals, priors [][]byte) bool {
	if len(vals) != len(priors) {
		return false
	}
	for k := range vals {
		if len(vals[k]) < reproMinMirror || !bytes.Contains(priors[k], vals[k]) {
			return false
		}
	}
	return true
}

// maximalMirrorMerge coalesces a run of consecutive pieces whose concatenation is
// a contiguous substring of the prior server in EVERY flow into ONE variable
// (mirror) slot — the greedy maximal-mirror extension. A long server-issued token
// the aligner split around a const (a bearer/gzip blob) becomes ONE verbatim
// mirror instead of two fragments. It is a strict no-op unless it actually spans
// more than the seed piece, so a slot that already mirrors whole is untouched.
func maximalMirrorMerge(pieces []piece, priors [][]byte) []piece {
	nF := len(priors)
	var out []piece
	i := 0
	for i < len(pieces) {
		p := pieces[i]
		if !p.isVar || !anyDiffer(p.vv) || !allInPriorContig(p.vv, priors) {
			out = append(out, p)
			i++
			continue
		}
		hi := i + 1
		for hi < len(pieces) && allInPriorContig(concatRange(pieces, i, hi+1, nF), priors) {
			hi++
		}
		if hi-i == 1 {
			out = append(out, p)
			i = hi
			continue
		}
		out = append(out, piece{isVar: true, vv: concatRange(pieces, i, hi, nF)})
		i = hi
	}
	return out
}

// subCarve splits any variable piece that embeds a reference substring into
// ordered const + typed sub-slots, leaving the classifier to type each piece.
func subCarve(pieces []piece, flagResps, priors [][]byte, earlier [][][]byte) []piece {
	var out []piece
	for _, p := range pieces {
		if !p.isVar {
			out = append(out, p)
			continue
		}
		if carved := carveVarPiece(p.vv, flagResps, priors, earlier); carved != nil {
			out = append(out, carved...)
			continue
		}
		out = append(out, p)
	}
	return out
}

type carveSpan struct{ start, backLen int }

// carveVarPiece finds the longest stable-offset SUBSTRING of a slot that matches
// (in priority order) the target flagId (echoed in the flag response), a prior-
// server value (mirror source), or an earlier client slot value (selfref), and
// splits the slot at it. Returns nil (keep the whole slot) when nothing matches.
func carveVarPiece(vals, flagResps, priors [][]byte, earlier [][][]byte) []piece {
	// A value echoed WHOLE in the flag response is a whole-slot flagId (or a whole
	// mirror/selfref): leave it to whole-slot classification, never fragment it.
	whole := true
	for k := range vals {
		if k >= len(flagResps) || valueIn(vals[k], flagResps[k]) == "" {
			whole = false
			break
		}
	}
	if whole {
		return nil
	}
	// (a) a flagId embedded as a substring echoed in the flag-bearing response.
	if sp := carveSpanEcho(vals, flagResps, carveFlagIDMin, true); sp != nil {
		if pieces := splitAtSpan(vals, sp); pieces != nil {
			return pieces
		}
	}
	// (b) a prior-server value embedded as a substring — accepted only when the
	// carved span validates as a real MIRROR, so a random field is never fragmented
	// on a chance prior-server coincidence.
	if sp := carveSpanEcho(vals, priors, reproMinMirror, false); sp != nil {
		if spans := spanValues(vals, sp); spans != nil && discoverMirror(spans, priors) != nil {
			if pieces := splitAtSpan(vals, sp); pieces != nil {
				return pieces
			}
		}
	}
	// (c) an earlier client slot value embedded as a substring (a credential reused
	// inside a larger field).
	if sp := carveSpanEarlier(vals, earlier); sp != nil {
		if pieces := splitAtSpan(vals, sp); pieces != nil {
			return pieces
		}
	}
	return nil
}

// carveSpanEcho locates the longest substring of the flow-0 value present in its
// reference (flag response / prior server), then VALIDATES the same stable offsets
// yield an in-reference, varying span in every flow. idShaped restricts the search
// to id-token runs and requires each span to look like an id (>= 2 char classes).
func carveSpanEcho(vals, refs [][]byte, minLen int, idShaped bool) *carveSpan {
	if len(vals) == 0 || len(refs) != len(vals) || len(vals[0]) == 0 {
		return nil
	}
	bs, be, ok := longestEchoed(vals[0], refs[0], minLen, idShaped)
	if !ok {
		return nil
	}
	start, backLen := bs, len(vals[0])-be
	if start == 0 && backLen == 0 {
		return nil // whole-slot match; leave it to whole-slot classification
	}
	spans := spanValues(vals, &carveSpan{start, backLen})
	if spans == nil {
		return nil
	}
	for k := range spans {
		if len(spans[k]) < minLen || !bytes.Contains(refs[k], spans[k]) {
			return nil
		}
		if idShaped && !isIDSpan(spans[k]) {
			return nil
		}
	}
	if !anyDiffer(spans) {
		return nil // a stable reference value is a const, not a carried dependency
	}
	return &carveSpan{start, backLen}
}

// carveSpanEarlier locates an earlier client slot value embedded (at a stable
// offset, as a proper substring, varying) inside this slot's value in every flow.
func carveSpanEarlier(vals [][]byte, earlier [][][]byte) *carveSpan {
	if len(earlier) != len(vals) || len(earlier) == 0 || len(vals[0]) == 0 {
		return nil
	}
	for e := 0; e < len(earlier[0]); e++ {
		ev0 := earlier[0][e]
		if len(ev0) < carveSelfrefMin {
			continue
		}
		idx := bytes.Index(vals[0], ev0)
		if idx < 0 {
			continue
		}
		start, backLen := idx, len(vals[0])-(idx+len(ev0))
		if start == 0 && backLen == 0 {
			continue
		}
		ok := true
		spans := make([][]byte, len(vals))
		for k := range vals {
			if e >= len(earlier[k]) {
				ok = false
				break
			}
			ev := earlier[k][e]
			if len(vals[k]) != start+len(ev)+backLen {
				ok = false
				break
			}
			sp := vals[k][start : len(vals[k])-backLen]
			if !bytes.Equal(sp, ev) {
				ok = false
				break
			}
			spans[k] = sp
		}
		if ok && anyDiffer(spans) {
			return &carveSpan{start, backLen}
		}
	}
	return nil
}

// spanValues extracts, per flow, the [start : len-backLen] sub-span; nil if any
// value is too short for the stable offsets.
func spanValues(vals [][]byte, sp *carveSpan) [][]byte {
	out := make([][]byte, len(vals))
	for k := range vals {
		if len(vals[k]) < sp.start+sp.backLen {
			return nil
		}
		out[k] = vals[k][sp.start : len(vals[k])-sp.backLen]
	}
	return out
}

// longestEchoed returns the [start,end) of the longest substring of v that is
// present in ref (>= minLen). idShaped confines candidates to id-token runs.
func longestEchoed(v, ref []byte, minLen int, idShaped bool) (int, int, bool) {
	n := len(v)
	best0, best1, bestLen := 0, 0, 0
	i := 0
	for i < n {
		j := n
		if idShaped {
			if !idByte(v[i]) {
				i++
				continue
			}
			j = i + 1
			for j < n && idByte(v[j]) {
				j++
			}
		}
		for a := i; a+minLen <= j; a++ {
			b := a + minLen
			if !bytes.Contains(ref, v[a:b]) {
				continue
			}
			for b < j && bytes.Contains(ref, v[a:b+1]) {
				b++
			}
			if b-a > bestLen {
				best0, best1, bestLen = a, b, b-a
			}
		}
		if idShaped {
			i = j
		} else {
			break
		}
	}
	if bestLen >= minLen {
		return best0, best1, true
	}
	return 0, 0, false
}

// splitAtSpan splits every flow's value into prefix + matched span + suffix,
// byte-aligning the (equal-length) prefix and suffix into const/var sub-pieces and
// emitting the matched span as one variable sub-slot. Returns nil if the split
// would not actually separate anything.
func splitAtSpan(vals [][]byte, sp *carveSpan) []piece {
	nF := len(vals)
	prefix := make([][]byte, nF)
	mid := make([][]byte, nF)
	suffix := make([][]byte, nF)
	for k := range vals {
		v := vals[k]
		if len(v) < sp.start+sp.backLen {
			return nil
		}
		prefix[k] = v[:sp.start]
		mid[k] = v[sp.start : len(v)-sp.backLen]
		suffix[k] = v[len(v)-sp.backLen:]
	}
	var out []piece
	out = append(out, byteAlignPieces(prefix)...)
	out = append(out, piece{isVar: true, vv: mid})
	out = append(out, byteAlignPieces(suffix)...)
	if len(out) < 2 {
		return nil
	}
	return out
}

// byteAlignPieces splits equal-length per-flow parts into maximal const/var runs
// by byte-wise agreement.
func byteAlignPieces(parts [][]byte) []piece {
	nF := len(parts)
	if nF == 0 {
		return nil
	}
	L := len(parts[0])
	if L == 0 {
		return nil
	}
	mask := make([]bool, L)
	for j := 0; j < L; j++ {
		c := parts[0][j]
		eq := true
		for k := 1; k < nF; k++ {
			if len(parts[k]) != L || parts[k][j] != c {
				eq = false
				break
			}
		}
		mask[j] = eq
	}
	var out []piece
	j := 0
	for j < L {
		v := mask[j]
		e := j + 1
		for e < L && mask[e] == v {
			e++
		}
		if v {
			out = append(out, piece{cb: append([]byte(nil), parts[0][j:e]...)})
		} else {
			vv := make([][]byte, nF)
			for k := range parts {
				vv[k] = append([]byte(nil), parts[k][j:e]...)
			}
			out = append(out, piece{isVar: true, vv: vv})
		}
		j = e
	}
	return out
}

func idByte(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		c == '.' || c == '_' || c == '%' || c == '-'
}

// isIDSpan reports an id-token-shaped carved span: bounded length, id charset, and
// at least two character classes (so a run of the same class is not carved out).
func isIDSpan(sp []byte) bool {
	if len(sp) < carveFlagIDMin || len(sp) > 64 {
		return false
	}
	if !reIDSel.Match(sp) {
		return false
	}
	// >= 2 of {lower, upper, digit}: a flagId mixes classes (a uuid is hex+hyphen);
	// a run of a single class (all digits, all lower) is not carved out.
	return charClassCount(string(sp)) >= 2
}

// trailingBackslashesOdd reports whether b ends in an ODD run of '\' — i.e. a
// dangling JSON escape-introducer that must not be orphaned before a slot.
func trailingBackslashesOdd(b []byte) bool {
	n := 0
	for i := len(b) - 1; i >= 0 && b[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
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
// HMAC/JWT-forge, external session token, unknown data param). It iterates the
// REFINED vslotIndex, so after sub-carve the COMPUTED verdict is localized to the
// offending SUB-slot: a formerly-opaque field whose reproducible part (an embedded
// flagId / mirror) was carved out no longer gates on that part — only its genuinely
// opaque residue can, and the gate reason names that residue's example.
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
