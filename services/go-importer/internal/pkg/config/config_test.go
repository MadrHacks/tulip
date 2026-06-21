package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestServiceByPort(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "services.yml")
	os.WriteFile(p, []byte("services:\n  - name: CCalendar\n    ports: [3000, 3001]\n  - name: ExCCel\n    ports: [5000]\n"), 0o644)
	servicesFile = &fileCache{path: p}

	m := ServiceByPort()
	want := map[int]string{3000: "CCalendar", 3001: "CCalendar", 5000: "ExCCel"}
	if len(m) != len(want) {
		t.Fatalf("got %d entries, want %d: %v", len(m), len(want), m)
	}
	for port, name := range want {
		if m[port] != name {
			t.Errorf("port %d = %q, want %q", port, m[port], name)
		}
	}
}

func TestScoreboardBaseURLAndTeamID(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "game.yml")
	os.WriteFile(p, []byte("gameserver_url: http://10.10.0.1:8080/flags\nteam_id: 36\n"), 0o644)
	gameFile = &fileCache{path: p}

	if got := ScoreboardBaseURL(); got != "http://10.10.0.1" {
		t.Errorf("ScoreboardBaseURL = %q, want http://10.10.0.1", got)
	}
	if got := TeamID(); got != 36 {
		t.Errorf("TeamID = %d, want 36", got)
	}
}
