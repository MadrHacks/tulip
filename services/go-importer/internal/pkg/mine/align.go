package mine

import "bytes"

// Segment is one piece of an aligned template: either a run of constant bytes
// shared by every member, or a variable slot where members differ.
type Segment struct {
	Const []byte // the constant bytes (nil/empty when Var)
	Var   bool   // true = a slot that differs across members
}

// token is a contiguous slice of one member's bytes.
type token []byte

// isWord reports whether b belongs to a maximal word run [A-Za-z0-9_].
func isWord(b byte) bool {
	return b == '_' ||
		(b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9')
}

// tokenize splits data into maximal word runs and single delimiter bytes.
func tokenize(data []byte) []token {
	toks := make([]token, 0, len(data)/3+1)
	i := 0
	for i < len(data) {
		if isWord(data[i]) {
			j := i + 1
			for j < len(data) && isWord(data[j]) {
				j++
			}
			toks = append(toks, token(data[i:j]))
			i = j
		} else {
			toks = append(toks, token(data[i:i+1]))
			i++
		}
	}
	return toks
}

// lcs returns, for the two token sequences, the indices of a longest common
// subsequence in a and the matching indices in b. Standard DP with a
// deterministic tie-break (prefer the up move, giving lowest indices).
func lcs(a, b []token) (ai, bi []int) {
	n, m := len(a), len(b)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if bytes.Equal(a[i], b[j]) {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	i, j := 0, 0
	for i < n && j < m {
		if bytes.Equal(a[i], b[j]) {
			ai = append(ai, i)
			bi = append(bi, j)
			i++
			j++
		} else if dp[i+1][j] >= dp[i][j+1] {
			i++
		} else {
			j++
		}
	}
	return ai, bi
}

// commonTokens returns the tokens common to every member, in order, by
// iteratively intersecting the running anchor with each subsequent member via
// the token-level LCS.
func commonTokens(membersToks [][]token) []token {
	anchor := append([]token(nil), membersToks[0]...)
	for _, mt := range membersToks[1:] {
		ai, _ := lcs(anchor, mt)
		next := make([]token, len(ai))
		for k, idx := range ai {
			next[k] = anchor[idx]
		}
		anchor = next
		if len(anchor) == 0 {
			break
		}
	}
	return anchor
}

// Align returns the template: an ordered list of segments. With a single member
// the whole input is one Const segment. With >= 2 members, maximal runs of
// tokens common to ALL members become Const segments, separated by Var slots
// wherever members differ. No two Var segments are ever adjacent.
func Align(members [][]byte) []Segment {
	if len(members) == 0 {
		return nil
	}
	if len(members) == 1 {
		if len(members[0]) == 0 {
			return nil
		}
		return []Segment{{Const: append([]byte(nil), members[0]...)}}
	}

	membersToks := make([][]token, len(members))
	for i, m := range members {
		membersToks[i] = tokenize(m)
	}

	common := commonTokens(membersToks)
	if len(common) == 0 {
		// Nothing shared: the whole thing is one variable slot.
		return []Segment{{Var: true}}
	}

	// For each member, the index just past each matched common token, so we can
	// detect intervening (variable) tokens between two adjacent common tokens in
	// ANY member, not just member 0.
	gapBefore := make([]bool, len(common)+1) // gapBefore[c]: variation before common[c]
	for _, mt := range membersToks {
		_, bi := lcs(common, mt)
		prev := 0
		for c := range common {
			if bi[c] > prev {
				gapBefore[c] = true
			}
			prev = bi[c] + 1
		}
		if prev < len(mt) {
			gapBefore[len(common)] = true
		}
	}

	segs := make([]Segment, 0, 8)
	var run []byte // accumulating constant bytes

	flushConst := func() {
		if len(run) > 0 {
			segs = append(segs, Segment{Const: run})
			run = nil
		}
	}
	appendVar := func() {
		// Merge with a trailing Var; never emit two adjacent Var segments.
		if n := len(segs); n > 0 && segs[n-1].Var {
			return
		}
		segs = append(segs, Segment{Var: true})
	}

	for c, tk := range common {
		if gapBefore[c] {
			flushConst()
			appendVar()
		}
		run = append(run, tk...)
	}
	if gapBefore[len(common)] {
		flushConst()
		appendVar()
	}
	flushConst()

	return segs
}
