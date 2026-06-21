package mine

import "testing"

const scoreboardFixture = `{
  "services": [
    { "name": "CCalendar-1", "shortname": "CCalendar-1", "vulnboxId": 0, "attackers": 6, "victims": 34 },
    { "name": "CCalendar-2", "shortname": "CCalendar-2", "vulnboxId": 0, "attackers": 3, "victims": 12 },
    { "name": "ExCCel", "shortname": "ExCCel", "vulnboxId": 1, "attackers": 1, "victims": 2 }
  ],
  "others": [],
  "scoreboard": [
    {
      "position": 1, "shortname": "unipi", "name": "University of Pisa",
      "nop": false, "guest": false, "teamId": 26, "logo": "unipi", "score": 93219.8,
      "services": [
        { "shortname": "CCalendar-1", "score": 17103.6, "stolen": 4300, "lost": 101,
          "attackerScore": 14200.5, "victimScore": -2096.8, "successfulChecks": 150, "totalChecks": 150,
          "checks": [
            { "action": "CHECK_SLA", "exitCode": 101, "stdout": "OK" },
            { "action": "GET_FLAG", "exitCode": 101, "stdout": "OK" },
            { "action": "PUT_FLAG", "exitCode": 101, "stdout": "OK" }
          ] },
        { "shortname": "CCalendar-2", "score": 900.0, "stolen": 200, "lost": 50,
          "attackerScore": 1000.0, "victimScore": -100.0, "successfulChecks": 100, "totalChecks": 100,
          "checks": [ { "action": "CHECK_SLA", "exitCode": 101, "stdout": "OK" } ] },
        { "shortname": "ExCCel", "score": 50.0, "stolen": 1, "lost": 2,
          "attackerScore": 5.0, "victimScore": -3.0, "successfulChecks": 40, "totalChecks": 50,
          "checks": [ { "action": "CHECK_SLA", "exitCode": 110, "stdout": "DOWN" } ] }
      ]
    },
    {
      "position": 2, "shortname": "unict", "name": "University of Catania",
      "nop": true, "guest": false, "teamId": 7, "logo": "unict", "score": 12000.0,
      "services": [
        { "shortname": "CCalendar-1", "score": 10.0, "stolen": 0, "lost": 500,
          "attackerScore": 0.0, "victimScore": -500.0, "successfulChecks": 0, "totalChecks": 0,
          "checks": [] }
      ]
    }
  ]
}`

func TestParseScoreboard(t *testing.T) {
	sb, err := ParseScoreboard([]byte(scoreboardFixture))
	if err != nil {
		t.Fatalf("ParseScoreboard: %v", err)
	}
	if len(sb.Scoreboard) != 2 {
		t.Fatalf("teams = %d, want 2", len(sb.Scoreboard))
	}
	t0 := sb.Scoreboard[0]
	if t0.Shortname != "unipi" || t0.TeamId != 26 || t0.Position != 1 || t0.Score != 93219.8 {
		t.Errorf("team0 = %+v", t0)
	}
	if t0.Nop {
		t.Errorf("team0 nop = true, want false")
	}
	if !sb.Scoreboard[1].Nop {
		t.Errorf("team1 nop = false, want true")
	}
	if len(t0.Services) != 3 {
		t.Fatalf("team0 services = %d, want 3", len(t0.Services))
	}
	if got := t0.Services[0].Checks; len(got) != 3 || got[1].Action != "GET_FLAG" {
		t.Errorf("team0 svc0 checks = %+v", got)
	}
}

func TestTeamServiceSignal(t *testing.T) {
	sb, err := ParseScoreboard([]byte(scoreboardFixture))
	if err != nil {
		t.Fatalf("ParseScoreboard: %v", err)
	}

	cases := []struct {
		name    string
		teamId  int
		service string
		want    ServiceSignal
	}{
		{
			name:    "multi-instance summed, SLA healthy",
			teamId:  26,
			service: "CCalendar",
			want: ServiceSignal{
				Stolen: 4500, Lost: 151,
				AttackerScore: 15200.5, VictimScore: -2196.8,
				SuccessfulChecks: 250, TotalChecks: 250, SLAHealthy: true,
			},
		},
		{
			name:    "single instance, SLA unhealthy (partial checks)",
			teamId:  26,
			service: "ExCCel",
			want: ServiceSignal{
				Stolen: 1, Lost: 2,
				AttackerScore: 5.0, VictimScore: -3.0,
				SuccessfulChecks: 40, TotalChecks: 50, SLAHealthy: false,
			},
		},
		{
			name:    "zero total checks is not healthy",
			teamId:  7,
			service: "CCalendar",
			want: ServiceSignal{
				Stolen: 0, Lost: 500,
				AttackerScore: 0.0, VictimScore: -500.0,
				SuccessfulChecks: 0, TotalChecks: 0, SLAHealthy: false,
			},
		},
		{
			name:    "unknown team yields zero signal",
			teamId:  999,
			service: "CCalendar",
			want:    ServiceSignal{},
		},
		{
			name:    "unknown service yields zero signal",
			teamId:  26,
			service: "Nope",
			want:    ServiceSignal{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sb.TeamServiceSignal(tc.teamId, tc.service)
			if got != tc.want {
				t.Errorf("TeamServiceSignal(%d, %q) = %+v, want %+v", tc.teamId, tc.service, got, tc.want)
			}
		})
	}
}
