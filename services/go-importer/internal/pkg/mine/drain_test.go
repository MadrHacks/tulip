package mine

import "testing"

// TestDrainCollapsesVaryingToken: N messages that share their structure but
// differ in one token position collapse to ONE template with a <*> wildcard at
// the varying position (post-normalization masking already removed high-entropy
// values; Drain generalizes the residual variation).
func TestDrainCollapsesVaryingToken(t *testing.T) {
	d := NewShapeGrouper()
	msgs := []string{
		"GET api user alpha",
		"GET api user beta",
		"GET api user gamma",
		"GET api user delta",
	}
	var ids []int
	for _, m := range msgs {
		ids = append(ids, d.Add(m))
	}
	for i, id := range ids {
		if id != ids[0] {
			t.Fatalf("msg %d got id %d, want %d (all collapse)", i, id, ids[0])
		}
	}
	if d.NumClusters() != 1 {
		t.Fatalf("clusters = %d, want 1", d.NumClusters())
	}
	if got := d.Template(ids[0]); got != "GET api user <*>" {
		t.Errorf("template = %q, want %q", got, "GET api user <*>")
	}
}

// TestDrainKeepsStructurallyDifferent: differing first token, differing token
// count, or sub-threshold similarity each yield a distinct template.
func TestDrainKeepsStructurallyDifferent(t *testing.T) {
	d := NewShapeGrouper()
	a := d.Add("GET a b c")  // baseline
	b := d.Add("GET x y z")  // same bucket, shares only 1/4 -> sim 0.25 < 0.6
	c := d.Add("POST a b c") // different first token -> different tree branch
	e := d.Add("GET a b")    // different token count
	ids := []int{a, b, c, e}
	seen := map[int]bool{}
	for i, id := range ids {
		if seen[id] {
			t.Errorf("id %d (msg %d) collapsed unexpectedly", id, i)
		}
		seen[id] = true
	}
	if d.NumClusters() != 4 {
		t.Fatalf("clusters = %d, want 4", d.NumClusters())
	}
}

// TestDrainStableIDsOnRepeat: an identical message returns the same id and does
// not create a new cluster.
func TestDrainStableIDsOnRepeat(t *testing.T) {
	d := NewShapeGrouper()
	id1 := d.Add("POST api login json{password,username}")
	id2 := d.Add("POST api login json{password,username}")
	if id1 != id2 {
		t.Fatalf("ids %d != %d for identical input", id1, id2)
	}
	if d.NumClusters() != 1 {
		t.Fatalf("clusters = %d, want 1", d.NumClusters())
	}
}

// TestDrainEmptyMessage: an empty skeleton is grouped under "<EMPTY>".
func TestDrainEmptyMessage(t *testing.T) {
	d := NewShapeGrouper()
	id := d.Add("")
	if got := d.Template(id); got != "<EMPTY>" {
		t.Errorf("empty template = %q, want <EMPTY>", got)
	}
}
