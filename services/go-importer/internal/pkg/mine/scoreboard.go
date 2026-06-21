package mine

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Scoreboard is a parsed CCIT scoreboard round (GET /api/scoreboard/table/{round}).
type Scoreboard struct {
	Scoreboard []ScoreTeam `json:"scoreboard"`
}

// ScoreTeam is one team's row, including its per-service-instance breakdown.
type ScoreTeam struct {
	Position  int            `json:"position"`
	Shortname string         `json:"shortname"`
	Name      string         `json:"name"`
	Nop       bool           `json:"nop"`
	Guest     bool           `json:"guest"`
	TeamId    int            `json:"teamId"`
	Score     float64        `json:"score"`
	Services  []ScoreService `json:"services"`
}

// ScoreService is a team's standing for a single service instance ("CCalendar-1").
type ScoreService struct {
	Shortname        string       `json:"shortname"`
	Score            float64      `json:"score"`
	Stolen           int          `json:"stolen"`
	Lost             int          `json:"lost"`
	AttackerScore    float64      `json:"attackerScore"`
	VictimScore      float64      `json:"victimScore"`
	SuccessfulChecks int          `json:"successfulChecks"`
	TotalChecks      int          `json:"totalChecks"`
	Checks           []ScoreCheck `json:"checks"`
}

// ScoreCheck is a single SLA check action result.
type ScoreCheck struct {
	Action   string `json:"action"`
	ExitCode int    `json:"exitCode"`
	Stdout   string `json:"stdout"`
}

// ServiceSignal is a team's standing for a logical service NAME, summed across
// all of that service's port instances.
type ServiceSignal struct {
	Stolen           int
	Lost             int
	AttackerScore    float64
	VictimScore      float64
	SuccessfulChecks int
	TotalChecks      int
	SLAHealthy       bool
}

// ParseScoreboard decodes a scoreboard round JSON document.
func ParseScoreboard(data []byte) (*Scoreboard, error) {
	var sb Scoreboard
	if err := json.Unmarshal(data, &sb); err != nil {
		return nil, err
	}
	return &sb, nil
}

// TeamServiceSignal aggregates a team's per-instance services up to the logical
// service NAME (via ServiceName), summing the correlation metrics across every
// instance. An unknown team or service yields a zero signal, not an error.
func (sb *Scoreboard) TeamServiceSignal(teamId int, serviceName string) ServiceSignal {
	var sig ServiceSignal
	for i := range sb.Scoreboard {
		t := &sb.Scoreboard[i]
		if t.TeamId != teamId {
			continue
		}
		for j := range t.Services {
			s := &t.Services[j]
			if ServiceName(s.Shortname) != serviceName {
				continue
			}
			sig.Stolen += s.Stolen
			sig.Lost += s.Lost
			sig.AttackerScore += s.AttackerScore
			sig.VictimScore += s.VictimScore
			sig.SuccessfulChecks += s.SuccessfulChecks
			sig.TotalChecks += s.TotalChecks
		}
	}
	sig.SLAHealthy = sig.TotalChecks > 0 && sig.SuccessfulChecks == sig.TotalChecks
	return sig
}

// FetchRound retrieves the raw scoreboard JSON for a round, sending browser-like
// headers so the gameserver serves JSON rather than HTML.
func FetchRound(baseURL string, round int) ([]byte, error) {
	url := fmt.Sprintf("%s/api/scoreboard/table/%d", baseURL, round)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
	req.Header.Set("Referer", baseURL+"/")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scoreboard round %d: status %d", round, resp.StatusCode)
	}
	return body, nil
}
