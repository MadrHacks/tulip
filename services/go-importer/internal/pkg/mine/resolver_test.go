package mine

import (
	"testing"

	"go-importer/internal/pkg/config"
)

func TestFoldServiceName(t *testing.T) {
	cases := map[string]string{
		"Control Tower": "controltower",
		"control-tower": "controltower",
		"CONTROLTOWER":  "controltower",
		"Sky_Pedia 2":   "skypedia2",
		"":              "",
	}
	for in, want := range cases {
		if got := foldServiceName(in); got != want {
			t.Errorf("foldServiceName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestServiceResolver(t *testing.T) {
	// Internal names come from vulnbox folders; scoreboard names differ in case
	// and separators. Fuzzy by default, exact via scoreboard_name.
	r := newServiceResolver([]config.ServiceDef{
		{Name: "skypedia"},
		{Name: "control-tower"},
		{Name: "dutyfree", ScoreboardName: "Duty Free"},
	})
	cases := map[string]string{
		"Skypedia":     "skypedia",      // capitalization folded
		"SKYPEDIA":     "skypedia",      // any case
		"ControlTower": "control-tower", // separator + case folded
		"Duty Free":    "dutyfree",      // explicit scoreboard_name override
		"DutyFree":     "dutyfree",      // fuzzy still works alongside the override
		"Unknown":      "Unknown",       // true miss returns unchanged
	}
	for in, want := range cases {
		if got := r.resolve(in); got != want {
			t.Errorf("resolve(%q) = %q, want %q", in, got, want)
		}
	}
}
