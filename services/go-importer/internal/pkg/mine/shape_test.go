package mine

import "testing"

func TestGroupShapesAggregatesSignals(t *testing.T) {
	units := []Unit{
		{TemplateID: 1, UA: "checker", Feats: RespFeatures{FlagPresent: true, ContentLengthBucket: 3}},
		{TemplateID: 1, UA: "checker", Feats: RespFeatures{FlagPresent: false, ContentLengthBucket: 2}},
		{TemplateID: 1, UA: "python-urllib3/2.7.0", Feats: RespFeatures{FlagPresent: true, ContentLengthBucket: 4}, FlagIn: true},
		{TemplateID: 2, UA: "checker", Feats: RespFeatures{FlagPresent: false, ContentLengthBucket: 1}},
	}
	shapes := GroupShapes(units, map[int]string{1: "GET api <*>", 2: "GET user"})
	if len(shapes) != 2 {
		t.Fatalf("shapes = %d, want 2", len(shapes))
	}
	s1 := shapes[0]
	if s1.TemplateID != 1 || s1.Template != "GET api <*>" || s1.Members != 3 {
		t.Fatalf("shape1 = %+v", s1)
	}
	if s1.Signals.FlagPresent != 2 {
		t.Errorf("flag_present = %d, want 2", s1.Signals.FlagPresent)
	}
	if s1.Signals.FlagIn != 1 {
		t.Errorf("flag_in = %d, want 1", s1.Signals.FlagIn)
	}
	if s1.Signals.SizeBucketSum != 9 {
		t.Errorf("size sum = %d, want 9", s1.Signals.SizeBucketSum)
	}
	if s1.Signals.Actors["checker"] != 2 || s1.Signals.Actors["python-urllib3/2.7.0"] != 1 {
		t.Errorf("actors = %v", s1.Signals.Actors)
	}
}

func TestSplitKeyPeelsOnFlagPresent(t *testing.T) {
	// Byte-identical client shape (same template id), split by response feature:
	// only flag_present differs -> two distinct split keys.
	benign := MakeSplitKey(7, RespFeatures{FlagPresent: false, HTTPStatus: 200, ContentType: "text/html"})
	exfil := MakeSplitKey(7, RespFeatures{FlagPresent: true, HTTPStatus: 200, ContentType: "text/html"})
	if benign == exfil {
		t.Fatal("flag_present did not split the shape")
	}
	// content_length_bucket must NOT be part of the key.
	a := MakeSplitKey(7, RespFeatures{FlagPresent: false, HTTPStatus: 200, ContentType: "text/html", ContentLengthBucket: 3})
	b := MakeSplitKey(7, RespFeatures{FlagPresent: false, HTTPStatus: 200, ContentType: "text/html", ContentLengthBucket: 9})
	if a != b {
		t.Fatal("content_length_bucket leaked into the split key")
	}
}

func TestSplitLabel(t *testing.T) {
	cases := []struct {
		f    RespFeatures
		want string
	}{
		{RespFeatures{FlagPresent: true, HTTPStatus: 200, ContentType: "application/json"}, "FLAG|200|application/json"},
		{RespFeatures{FlagPresent: false, HTTPStatus: 403, ContentType: "application/json"}, "noflag|403|application/json"},
		{RespFeatures{FlagPresent: true, ContentType: "line"}, "FLAG|line"},
		{RespFeatures{FlagPresent: false}, "noflag"},
	}
	for _, tc := range cases {
		if got := SplitLabel(tc.f); got != tc.want {
			t.Errorf("SplitLabel(%+v) = %q, want %q", tc.f, got, tc.want)
		}
	}
}

func TestSessionShape(t *testing.T) {
	if got := SessionShape([]int{3, 1, 3, 7}); got != "3>1>3>7" {
		t.Errorf("session sig = %q", got)
	}
	if got := SessionShape(nil); got != "<EMPTY-FLOW>" {
		t.Errorf("empty flow sig = %q", got)
	}
	// order matters: a different order is a different session shape.
	if SessionShape([]int{1, 2}) == SessionShape([]int{2, 1}) {
		t.Error("session shape ignored order")
	}
}
