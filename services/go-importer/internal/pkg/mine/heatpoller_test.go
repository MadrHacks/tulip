package mine

import (
	"testing"
	"time"
)

func TestRoundForTime(t *testing.T) {
	start := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	tick := 120 * time.Second

	cases := []struct {
		name string
		now  time.Time
		want int
	}{
		{"at start", start, 0},
		{"mid first tick", start.Add(60 * time.Second), 0},
		{"third tick", start.Add(250 * time.Second), 2},
		{"before start", start.Add(-time.Second), -1},
	}
	for _, c := range cases {
		if got := roundForTime(start, c.now, tick); got != c.want {
			t.Errorf("%s: round = %d, want %d", c.name, got, c.want)
		}
	}

	if got := roundForTime(start, start.Add(time.Hour), 0); got != -1 {
		t.Errorf("non-positive tick should give -1, got %d", got)
	}
}

func TestParseGameStart(t *testing.T) {
	if parseGameStart("2026-06-21T12:00:00Z").IsZero() {
		t.Error("RFC3339 start should parse")
	}
	if parseGameStart("2026-06-21 12:00:00").IsZero() {
		t.Error("space-separated start should parse")
	}
	if !parseGameStart("").IsZero() {
		t.Error("empty start should be the zero time (poller disabled)")
	}
	if !parseGameStart("not a time").IsZero() {
		t.Error("garbage start should be the zero time (poller disabled)")
	}
}
