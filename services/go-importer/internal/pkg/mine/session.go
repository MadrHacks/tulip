package mine

import "sort"

// Sessions groups flows into connected components (exploit sessions) using a
// weighted union-find, with a hard cap on component size to guard against a
// single spurious edge merging unrelated flows into a giant component.
type Sessions struct {
	parent map[string]string
	size   map[string]int
	cap    int
}

// NewSessions returns a Sessions with the given component-size cap.
// A cap <= 0 means unbounded.
func NewSessions(maxComponentSize int) *Sessions {
	return &Sessions{
		parent: make(map[string]string),
		size:   make(map[string]int),
		cap:    maxComponentSize,
	}
}

func (s *Sessions) ensure(flow string) {
	if _, ok := s.parent[flow]; !ok {
		s.parent[flow] = flow
		s.size[flow] = 1
	}
}

// Find returns the root of flow's component, with path compression. An unseen
// flow is lazily created as its own root.
func (s *Sessions) Find(flow string) string {
	s.ensure(flow)
	root := flow
	for s.parent[root] != root {
		root = s.parent[root]
	}
	for s.parent[flow] != root {
		s.parent[flow], flow = root, s.parent[flow]
	}
	return root
}

// Link unions the components of a and b by size. It returns false without
// merging if the combined size would exceed the cap. It returns true if the
// union succeeds or a and b are already in the same component.
func (s *Sessions) Link(a, b string) bool {
	ra, rb := s.Find(a), s.Find(b)
	if ra == rb {
		return true
	}
	combined := s.size[ra] + s.size[rb]
	if s.cap > 0 && combined > s.cap {
		return false
	}
	if s.size[ra] < s.size[rb] {
		ra, rb = rb, ra
	}
	s.parent[rb] = ra
	s.size[ra] = combined
	return true
}

// Apply links the endpoints of an edge.
func (s *Sessions) Apply(e Edge) bool {
	return s.Link(e.Src, e.Dst)
}

// Members returns all flows in flow's component, sorted for determinism.
func (s *Sessions) Members(flow string) []string {
	root := s.Find(flow)
	var out []string
	for f := range s.parent {
		if s.Find(f) == root {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// Size returns the number of flows in flow's component.
func (s *Sessions) Size(flow string) int {
	return s.size[s.Find(flow)]
}
