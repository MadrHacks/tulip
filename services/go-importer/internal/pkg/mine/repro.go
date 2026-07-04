package mine

// Protocol-agnostic reproduction engine, ported faithfully from the validated
// reference (scratchpad/repro-engine: engine.py + shape.py). For one attack
// SHAPE — a group of same-skeleton flows — it:
//
//	ALIGN    -> const/variable segments per ordered client message (token-level).
//	CLASSIFY each variable run: FLAGID | MIRROR(transform,delims) | SELFREF |
//	         RANDOM | LENGTH | COMPUTED (the last GATES the whole plan).
//	MINIMIZE -> keep the connection prefix through the flag-retrieving step,
//	         dropping only provable self-loop plants.
//	EMIT     -> an InteractivePlan: ordered send/recv with typed slots + Links.
//	GATE     -> COMPUTED slot / TLS-opaque / WS-framed / flag-not-in-cleartext ->
//	         UNREPRODUCIBLE (recorded with a reason, never emitted as a broken plan).
//
// The engine is deliberately CONSERVATIVE: anything it cannot mechanically prove
// regenerable is COMPUTED (gated), never a silent "random". That is what keeps a
// crypto vault from ever looking reproducible.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"

	"go-importer/internal/pkg/db"
)

const (
	reproMinMirror    = 6 // a mirror source substring must be at least this long
	reproFlagIDMinLen = 3
	reproAlignSample  = 24 // evenly-spaced build instances aligned per shape
)

// ---------------------------------------------------------------- flow helpers
// A shape member is one flow's ordered turns (db.FlowTurns). These mirror the
// reference Flow model: the turn ORDER is the only causal fact — a MIRROR of
// client turn j may only come from a server turn strictly before j.

func clientTurns(turns []db.Turn) [][]byte {
	var out [][]byte
	for _, t := range turns {
		if t.FromClient {
			out = append(out, t.Data)
		}
	}
	return out
}

func serverAll(turns []db.Turn) []byte {
	var out []byte
	for _, t := range turns {
		if !t.FromClient {
			out = append(out, t.Data...)
		}
	}
	return out
}

// priorServer is the concatenated server bytes emitted strictly before the
// clientIdx-th client turn.
func priorServer(turns []db.Turn, clientIdx int) []byte {
	seen := 0
	var out []byte
	for _, t := range turns {
		if t.FromClient {
			if seen == clientIdx {
				break
			}
			seen++
		} else {
			out = append(out, t.Data...)
		}
	}
	return out
}

// responsesPaired returns, aligned with clientTurns(), the server bytes that
// follow each client turn up to the next client turn.
func responsesPaired(turns []db.Turn) [][]byte {
	var buckets [][]byte
	for _, t := range turns {
		if t.FromClient {
			buckets = append(buckets, nil)
		} else if n := len(buckets); n > 0 {
			buckets[n-1] = append(buckets[n-1], t.Data...)
		} else {
			buckets = append(buckets, append([]byte(nil), t.Data...), nil)
		}
	}
	return buckets
}

func flagOf(turns []db.Turn, flagRe *regexp.Regexp) []byte {
	return flagRe.Find(serverAll(turns))
}

// ---------------------------------------------------------------- tokenizer
// value chars = those inside ids/tokens/base64url/JWT (incl . _ - ~). Every
// structural delimiter becomes its own single-byte token, so a const delimiter
// splits fields but a delimiter inside a high-entropy blob stays in the run.
// tokenize is exact: concat(tokens) == input.

func refWordByte(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		c == '_' || c == '.' || c == '~' || c == '-'
}

func refTokenize(data []byte) [][]byte {
	var toks [][]byte
	i := 0
	for i < len(data) {
		if refWordByte(data[i]) {
			j := i + 1
			for j < len(data) && refWordByte(data[j]) {
				j++
			}
			toks = append(toks, data[i:j])
			i = j
		} else {
			toks = append(toks, data[i:i+1])
			i++
		}
	}
	return toks
}

// ---------------------------------------------------------------- alignment
type alignSeg struct {
	isVar bool
	data  []byte
}

type turnAlign struct {
	segs    []alignSeg
	vranges [][2]int
}

// findLongestMatch is a faithful port of difflib.SequenceMatcher's
// find_longest_match (no junk): the leftmost longest contiguous block of a[alo:ahi]
// that also occurs in b[blo:bhi]. b2j maps each token to its ascending indices in b.
func findLongestMatch(a [][]byte, b2j map[string][]int, alo, ahi, blo, bhi int) (int, int, int) {
	besti, bestj, bestsize := alo, blo, 0
	j2len := map[int]int{}
	for i := alo; i < ahi; i++ {
		newj2len := map[int]int{}
		for _, j := range b2j[string(a[i])] {
			if j < blo {
				continue
			}
			if j >= bhi {
				break
			}
			k := j2len[j-1] + 1
			newj2len[j] = k
			if k > bestsize {
				besti, bestj, bestsize = i-k+1, j-k+1, k
			}
		}
		j2len = newj2len
	}
	return besti, bestj, bestsize
}

// matchingBlocks ports difflib.SequenceMatcher.get_matching_blocks: the ordered
// list of maximal contiguous (ai, bi, size) matches, found longest-first by
// recursive splitting. Reproducing difflib exactly keeps alignTurn's const mask
// byte-identical to the reference engine.
func matchingBlocks(a, b [][]byte) [][3]int {
	b2j := map[string][]int{}
	for j, tok := range b {
		key := string(tok)
		b2j[key] = append(b2j[key], j)
	}
	type span struct{ alo, ahi, blo, bhi int }
	queue := []span{{0, len(a), 0, len(b)}}
	var blocks [][3]int
	for len(queue) > 0 {
		q := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		i, j, k := findLongestMatch(a, b2j, q.alo, q.ahi, q.blo, q.bhi)
		if k > 0 {
			blocks = append(blocks, [3]int{i, j, k})
			if q.alo < i && q.blo < j {
				queue = append(queue, span{q.alo, i, q.blo, j})
			}
			if i+k < q.ahi && j+k < q.bhi {
				queue = append(queue, span{i + k, q.ahi, j + k, q.bhi})
			}
		}
	}
	return blocks
}

// difflibCoverage marks the ref tokens covered by a matching block with other —
// the tokens ref shares with other, per difflib's greedy longest-match blocks.
func difflibCoverage(ref, other [][]byte) []bool {
	cov := make([]bool, len(ref))
	for _, blk := range matchingBlocks(ref, other) {
		for i := blk[0]; i < blk[0]+blk[2]; i++ {
			cov[i] = true
		}
	}
	return cov
}

// alignTurn aligns the same client-message position across N instances. A ref
// token is CONST iff it is covered by a difflib matching block in EVERY other
// instance; maximal same-mask runs become segments (const runs -> long unique
// anchors; variable runs -> slots).
func alignTurn(streams [][]byte) turnAlign {
	ref := refTokenize(streams[0])
	n := len(ref)
	mask := make([]bool, n)
	for i := range mask {
		mask[i] = true
	}
	for _, other := range streams[1:] {
		cov := difflibCoverage(ref, refTokenize(other))
		for i := 0; i < n; i++ {
			if !cov[i] {
				mask[i] = false
			}
		}
	}
	var segs []alignSeg
	var vranges [][2]int
	i := 0
	for i < n {
		v := mask[i]
		j := i
		for j < n && mask[j] == v {
			j++
		}
		var b []byte
		for k := i; k < j; k++ {
			b = append(b, ref[k]...)
		}
		if v {
			segs = append(segs, alignSeg{isVar: false, data: b})
		} else {
			segs = append(segs, alignSeg{isVar: true, data: b})
			vranges = append(vranges, [2]int{i, j})
		}
		i = j
	}
	return turnAlign{segs: segs, vranges: vranges}
}

func indexFrom(data, sub []byte, from int) int {
	if from > len(data) {
		return -1
	}
	i := bytes.Index(data[from:], sub)
	if i < 0 {
		return -1
	}
	return from + i
}

// extractRunValues pulls each variable segment's value out of one instance by
// locating the const segments (long unique anchors) in order with a cursor.
func extractRunValues(al turnAlign, data []byte) [][]byte {
	cursor := 0
	// Non-nil empty so a const-only turn (zero variable slots) returns a valid
	// empty result, distinct from nil which signals a missing anchor (failure).
	vals := [][]byte{}
	for i, s := range al.segs {
		if !s.isVar {
			p := indexFrom(data, s.data, cursor)
			if p < 0 {
				return nil
			}
			cursor = p + len(s.data)
			continue
		}
		nxt, hasNext := []byte(nil), false
		for k := i + 1; k < len(al.segs); k++ {
			if !al.segs[k].isVar {
				nxt = al.segs[k].data
				hasNext = true
				break
			}
		}
		if !hasNext {
			vals = append(vals, append([]byte(nil), data[cursor:]...))
			cursor = len(data)
		} else {
			fp := indexFrom(data, nxt, cursor)
			if fp < 0 {
				return nil
			}
			vals = append(vals, append([]byte(nil), data[cursor:fp]...))
		}
	}
	return vals
}

// slotOffsets is the byte offset (in the ref) where each variable segment starts
// — to tell URL-positioned selectors (in the request line) from body fields.
func slotOffsets(al turnAlign) []int {
	var offs []int
	pos := 0
	for _, s := range al.segs {
		if s.isVar {
			offs = append(offs, pos)
		}
		pos += len(s.data)
	}
	return offs
}

// ---------------------------------------------------------------- transforms
// Each transform maps a client value to the representation to SEARCH for in a
// server response (toServer, nil = not applicable), and back (fromServer).

type reproTransform struct {
	name       string
	toServer   func([]byte) []byte
	fromServer func([]byte) []byte
}

var (
	reB64Valid = regexp.MustCompile(`^[A-Za-z0-9+/_-]+={0,2}$`)
	reHexAll   = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

func b64Decode(v []byte) []byte {
	if len(v) < 8 || !reB64Valid.Match(v) {
		return nil
	}
	body := bytes.TrimRight(v, "=")
	var enc *base64.Encoding
	if bytes.ContainsAny(body, "-_") {
		enc = base64.RawURLEncoding
	} else {
		enc = base64.RawStdEncoding
	}
	d, err := enc.DecodeString(string(body))
	if err != nil || len(d) < reproMinMirror {
		return nil
	}
	return d
}

func hexDecode(v []byte) []byte {
	if len(v) < 8 || len(v)%2 != 0 || !reHexAll.Match(v) {
		return nil
	}
	d, err := hex.DecodeString(string(v))
	if err != nil {
		return nil
	}
	return d
}

func urlDecode(v []byte) []byte {
	s, err := url.PathUnescape(string(v))
	if err != nil || s == string(v) {
		return nil
	}
	return []byte(s)
}

func urlEncode(x []byte) []byte {
	var b []byte
	const upper = "0123456789ABCDEF"
	for _, c := range x {
		b = append(b, '%', upper[c>>4], upper[c&0xf])
	}
	return b
}

var reproTransforms = []reproTransform{
	{"identity", func(v []byte) []byte { return v }, func(x []byte) []byte { return x }},
	{"b64decode", b64Decode, func(x []byte) []byte {
		return []byte(base64.StdEncoding.EncodeToString(x))
	}},
	{"b64encode", func(v []byte) []byte {
		return []byte(base64.StdEncoding.EncodeToString(v))
	}, func(x []byte) []byte {
		d, err := base64.StdEncoding.DecodeString(string(x) + "==")
		if err != nil {
			return nil
		}
		return d
	}},
	{"hexdecode", hexDecode, func(x []byte) []byte {
		return []byte(hex.EncodeToString(x))
	}},
	{"hexencode", func(v []byte) []byte {
		return []byte(hex.EncodeToString(v))
	}, func(x []byte) []byte {
		d, err := hex.DecodeString(string(x))
		if err != nil {
			return nil
		}
		return d
	}},
	{"urldecode", urlDecode, urlEncode},
}

func transformFrom(name string) func([]byte) []byte {
	for _, t := range reproTransforms {
		if t.name == name {
			return t.fromServer
		}
	}
	return nil
}

// ---------------------------------------------------------------- mirror discovery
type mirrorInfo struct {
	transform string
	prefix    []byte
	suffix    []byte
}

func commonSuffix(seqs [][]byte) []byte {
	if len(seqs) == 0 {
		return nil
	}
	m := len(seqs[0])
	for _, s := range seqs[1:] {
		if len(s) < m {
			m = len(s)
		}
	}
	var out []byte
	for k := 1; k <= m; k++ {
		c := seqs[0][len(seqs[0])-k]
		ok := true
		for _, s := range seqs {
			if s[len(s)-k] != c {
				ok = false
				break
			}
		}
		if !ok {
			break
		}
		out = append([]byte{c}, out...)
	}
	return out
}

func commonPrefix(seqs [][]byte) []byte {
	if len(seqs) == 0 {
		return nil
	}
	m := len(seqs[0])
	for _, s := range seqs[1:] {
		if len(s) < m {
			m = len(s)
		}
	}
	var out []byte
	for k := 0; k < m; k++ {
		c := seqs[0][k]
		ok := true
		for _, s := range seqs {
			if s[k] != c {
				ok = false
				break
			}
		}
		if !ok {
			break
		}
		out = append(out, c)
	}
	return out
}

func lastN(b []byte, n int) []byte {
	if len(b) > n {
		return b[len(b)-n:]
	}
	return b
}

func firstN(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

var reMirrorTrim = regexp.MustCompile(`["'=:,;&/?` + "\r\n" + `{}\[\] ][^"'=:,;&/?` + "\r\n" + `{}\[\] ]{0,20}$`)

func extractViaDelims(name string, pre, suf, server []byte) []byte {
	p := bytes.Index(server, pre)
	if p < 0 {
		return nil
	}
	start := p + len(pre)
	var rep []byte
	if len(suf) > 0 {
		e := indexFrom(server, suf, start)
		if e < 0 {
			return nil
		}
		rep = server[start:e]
	} else {
		rep = server[start:]
	}
	if fn := transformFrom(name); fn != nil {
		return fn(rep)
	}
	return nil
}

func validateDelims(name string, pre, suf []byte, slotVals, priorServers [][]byte) bool {
	for i := range slotVals {
		got := extractViaDelims(name, pre, suf, priorServers[i])
		if !bytes.Equal(got, slotVals[i]) {
			return false
		}
	}
	return true
}

// discoverMirror tries each transform in order; a mirror needs the transformed
// value present in EVERY instance's prior server. It then derives stable
// (prefix,suffix) delimiters and VALIDATES they re-extract every instance's exact
// value (guarding over-fit). First transform that validates wins.
func discoverMirror(slotVals, priorServers [][]byte) *mirrorInfo {
	for _, tf := range reproTransforms {
		reps := make([][]byte, 0, len(slotVals))
		ok := true
		for _, v := range slotVals {
			r := tf.toServer(v)
			if len(r) < reproMinMirror {
				ok = false
				break
			}
			reps = append(reps, r)
		}
		if !ok {
			continue
		}
		pos := make([]int, len(reps))
		for i, r := range reps {
			p := bytes.Index(priorServers[i], r)
			if p < 0 {
				ok = false
				break
			}
			pos[i] = p
		}
		if !ok {
			continue
		}
		befores := make([][]byte, len(reps))
		afters := make([][]byte, len(reps))
		for i := range reps {
			befores[i] = priorServers[i][:pos[i]]
			afters[i] = priorServers[i][pos[i]+len(reps[i]):]
		}
		pre := lastN(commonSuffix(befores), 40)
		suf := firstN(commonPrefix(afters), 40)
		if !validateDelims(tf.name, pre, suf, slotVals, priorServers) {
			if loc := reMirrorTrim.FindIndex(pre); loc != nil {
				pre2 := pre[loc[0]:]
				if !validateDelims(tf.name, pre2, suf, slotVals, priorServers) {
					continue
				}
				pre = pre2
			} else {
				continue
			}
		}
		return &mirrorInfo{transform: tf.name, prefix: pre, suffix: suf}
	}
	return nil
}

// ---------------------------------------------------------------- random / structure
var (
	reJWT       = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
	reDigits    = regexp.MustCompile(`^[0-9]+$`)
	reHexLower  = regexp.MustCompile(`^[0-9a-f]+$`)
	reHEX       = regexp.MustCompile(`^[0-9A-F]+$`)
	reLower     = regexp.MustCompile(`^[a-z]+$`)
	reAlnum     = regexp.MustCompile(`^[A-Za-z0-9]+$`)
	reTokenChar = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	rePrintable = regexp.MustCompile(`^[!-~]+$`)
)

func isStructuredToken(v []byte) bool {
	if reJWT.Match(v) {
		return true
	}
	if bytes.HasPrefix(v, []byte("H4sI")) {
		return true
	}
	if bytes.HasPrefix(v, []byte("eyJ")) {
		return true
	}
	return false
}

// charsetClass returns the tightest alphabet class covering every value, or "".
func charsetClass(vals [][]byte) string {
	a := bytes.Join(vals, nil)
	if len(a) == 0 {
		return ""
	}
	switch {
	case reDigits.Match(a):
		return "digits"
	case reHexLower.Match(a):
		return "hex-lower"
	case reHEX.Match(a):
		return "HEX"
	case reLower.Match(a):
		return "lower"
	case reAlnum.Match(a):
		return "alnum"
	case reTokenChar.Match(a):
		return "token-chars"
	case rePrintable.Match(a):
		return "printable"
	}
	return ""
}

type randomInfo struct {
	charset string
	minLen  int
	maxLen  int
}

func distinct(vals [][]byte) int {
	seen := map[string]struct{}{}
	for _, v := range vals {
		seen[string(v)] = struct{}{}
	}
	return len(seen)
}

// classifyRandom accepts a slot as a client-invented nonce/credential only when
// it actually varies, is not a structured token, and sits in a credential
// context (single-use high-entropy is NOT trusted). A fixed-width nonce must not
// vary in length unless it is a credential.
func classifyRandom(vals [][]byte, credCtx bool) *randomInfo {
	if distinct(vals) < 2 {
		return nil
	}
	for _, v := range vals {
		if isStructuredToken(v) {
			return nil
		}
	}
	if !credCtx {
		return nil
	}
	mn, mx := len(vals[0]), len(vals[0])
	for _, v := range vals {
		if len(v) < mn {
			mn = len(v)
		}
		if len(v) > mx {
			mx = len(v)
		}
	}
	if mx-mn > 2 && !credCtx {
		return nil
	}
	cs := charsetClass(vals)
	if cs == "" {
		return nil
	}
	return &randomInfo{charset: cs, minLen: mn, maxLen: mx}
}

// ---------------------------------------------------------------- flag / crypto helpers
func flagForms(flag []byte) [][]byte {
	return [][]byte{
		flag,
		[]byte(hex.EncodeToString(flag)),
		[]byte(base64.StdEncoding.EncodeToString(flag)),
	}
}

var (
	reHex16     = regexp.MustCompile(`^[0-9a-f]{16,}$`)
	reHEX16     = regexp.MustCompile(`^[0-9A-F]{16,}$`)
	reCryptoB64 = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{16,}$`)
	reIDSel     = regexp.MustCompile(`^[A-Za-z0-9._%-]+$`)
	reHexOnly   = regexp.MustCompile(`^[0-9a-f]+$`)
)

var cryptoHints = [][]byte{
	[]byte("challenge"), []byte("Challenge"), []byte("nonce"), []byte("Nonce"), []byte("signature"),
}

// looksCrypto reports a COMPUTED crypto artefact: a fixed-length hash/hex, or a
// value bracketed by a server 'challenge'/'nonce' prompt (=> derived from server
// data, not free).
func looksCrypto(vals, priorServers [][]byte) bool {
	allHex := true
	allHEX := true
	for _, v := range vals {
		if !(reHex16.Match(v) && len(v)%8 == 0) {
			allHex = false
		}
		if !(reHEX16.Match(v) && len(v)%8 == 0) {
			allHEX = false
		}
	}
	if allHex || allHEX {
		return true
	}
	if len(priorServers) > 0 {
		allHinted := true
		for _, ps := range priorServers {
			hinted := false
			for _, h := range cryptoHints {
				if bytes.Contains(ps, h) {
					hinted = true
					break
				}
			}
			if !hinted {
				allHinted = false
				break
			}
		}
		if allHinted {
			allB64 := true
			for _, v := range vals {
				if !reCryptoB64.Match(v) {
					allB64 = false
					break
				}
			}
			if allB64 {
				return true
			}
		}
	}
	return false
}

// looksIDSelector reports an externally-supplied record selector (flagId) shape:
// an id-like token, NOT a hash.
func looksIDSelector(vals [][]byte) bool {
	if len(vals) == 0 {
		return false
	}
	mn, mx := len(vals[0]), len(vals[0])
	for _, v := range vals {
		if len(v) < mn {
			mn = len(v)
		}
		if len(v) > mx {
			mx = len(v)
		}
	}
	if mx > 64 || mn < 4 {
		return false
	}
	for _, v := range vals {
		if !reIDSel.Match(v) {
			return false
		}
	}
	allHex := true
	for _, v := range vals {
		if !reHexOnly.Match(v) {
			allHex = false
			break
		}
	}
	if allHex && mn >= 16 {
		return false
	}
	return true
}

// valueIn reports whether v (identity or a simple decode) is present in blob,
// returning the transform name.
func valueIn(v, blob []byte) string {
	if len(v) < reproFlagIDMinLen {
		return ""
	}
	if bytes.Contains(blob, v) {
		return "identity"
	}
	if d := hexDecode(v); d != nil && bytes.Contains(blob, d) {
		return "hexdecode"
	}
	if d := b64Decode(v); d != nil && bytes.Contains(blob, d) {
		return "b64decode"
	}
	return ""
}
