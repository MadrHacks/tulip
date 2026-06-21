package mine

import (
	"sort"
	"strings"
)

// SessionFlow is a flow participating in an exploit session: its id, its
// single-flow cluster tag, and its timestamp.
type SessionFlow struct {
	Flow      string
	ClusterID string
	T         int64
}

// SessionSignature builds a canonical, deterministic signature for a session.
// The same set of flows + edges in any input order yields an identical result.
func SessionSignature(flows []SessionFlow, edges []Edge) string {
	ordered := make([]SessionFlow, len(flows))
	copy(ordered, flows)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].T != ordered[j].T {
			return ordered[i].T < ordered[j].T
		}
		return ordered[i].Flow < ordered[j].Flow
	})

	steps := make([]string, len(ordered))
	index := make(map[string]int, len(ordered))
	for i, f := range ordered {
		steps[i] = f.ClusterID
		index[f.Flow] = i
	}

	var pairs []string
	for _, e := range edges {
		si, sok := index[e.Src]
		di, dok := index[e.Dst]
		if !sok || !dok {
			continue
		}
		pairs = append(pairs, itoa(si)+"-"+itoa(di))
	}
	sort.Strings(pairs)

	return strings.Join(steps, ">") + "|" + strings.Join(pairs, ",")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
