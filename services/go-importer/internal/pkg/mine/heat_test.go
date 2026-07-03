package mine

import "testing"

func TestServiceHeat(t *testing.T) {
	sb := &Scoreboard{
		Scoreboard: []ScoreTeam{
			{
				TeamId: 1, // our team
				Services: []ScoreService{
					{Shortname: "CCalendar-1", Stolen: 3, Lost: 2, SuccessfulChecks: 5, TotalChecks: 5},
					{Shortname: "CCalendar-2", Stolen: 4, Lost: 1, SuccessfulChecks: 5, TotalChecks: 5},
					{Shortname: "CMail", Stolen: 1, Lost: 7, SuccessfulChecks: 2, TotalChecks: 5},
				},
			},
			{
				TeamId: 2,
				Services: []ScoreService{
					{Shortname: "CCalendar-1", Stolen: 10, Lost: 0, SuccessfulChecks: 5, TotalChecks: 5},
					{Shortname: "CCalendar-2", Stolen: 6, Lost: 0, SuccessfulChecks: 5, TotalChecks: 5},
					{Shortname: "CMail", Stolen: 2, Lost: 0, SuccessfulChecks: 5, TotalChecks: 5},
				},
			},
			{
				TeamId: 3,
				Services: []ScoreService{
					{Shortname: "CCalendar-1", Stolen: 5, Lost: 0, SuccessfulChecks: 5, TotalChecks: 5},
				},
			},
		},
	}

	heat := ServiceHeat(sb, 1, newServiceResolver(nil))

	cal, ok := heat["CCalendar"]
	if !ok {
		t.Fatalf("CCalendar missing from heat map")
	}

	// TotalStolen sums all teams + both instances: (3+4)+(10+6)+5 = 28.
	if cal.TotalStolen != 28 {
		t.Errorf("CCalendar TotalStolen = %d, want 28", cal.TotalStolen)
	}
	// Our stolen across both instances: 3+4 = 7.
	if cal.OurStolen != 7 {
		t.Errorf("CCalendar OurStolen = %d, want 7", cal.OurStolen)
	}
	// Our lost across both instances: 2+1 = 3.
	if cal.OurLost != 3 {
		t.Errorf("CCalendar OurLost = %d, want 3", cal.OurLost)
	}
	// All our CCalendar instances pass.
	if !cal.OurSLAOk {
		t.Errorf("CCalendar OurSLAOk = false, want true")
	}

	mail, ok := heat["CMail"]
	if !ok {
		t.Fatalf("CMail missing from heat map")
	}
	// TotalStolen: 1 (ours) + 2 (team2) = 3.
	if mail.TotalStolen != 3 {
		t.Errorf("CMail TotalStolen = %d, want 3", mail.TotalStolen)
	}
	if mail.OurStolen != 1 {
		t.Errorf("CMail OurStolen = %d, want 1", mail.OurStolen)
	}
	if mail.OurLost != 7 {
		t.Errorf("CMail OurLost = %d, want 7", mail.OurLost)
	}
	// Our CMail instance fails its checks -> not ok.
	if mail.OurSLAOk {
		t.Errorf("CMail OurSLAOk = true, want false")
	}

	// Unknown service is absent.
	if _, ok := heat["CNope"]; ok {
		t.Errorf("unknown service CNope unexpectedly present")
	}
}

func TestServiceHeatSLAFailsIfAnyInstanceFails(t *testing.T) {
	sb := &Scoreboard{
		Scoreboard: []ScoreTeam{
			{
				TeamId: 1,
				Services: []ScoreService{
					{Shortname: "CCalendar-1", SuccessfulChecks: 5, TotalChecks: 5},
					{Shortname: "CCalendar-2", SuccessfulChecks: 4, TotalChecks: 5},
				},
			},
		},
	}
	heat := ServiceHeat(sb, 1, newServiceResolver(nil))
	if heat["CCalendar"].OurSLAOk {
		t.Errorf("OurSLAOk = true, want false when one instance fails")
	}
}

func TestServiceHeatSLANotOkWithoutChecks(t *testing.T) {
	sb := &Scoreboard{
		Scoreboard: []ScoreTeam{
			{
				TeamId: 1,
				Services: []ScoreService{
					{Shortname: "CMail", SuccessfulChecks: 0, TotalChecks: 0},
				},
			},
		},
	}
	heat := ServiceHeat(sb, 1, newServiceResolver(nil))
	if heat["CMail"].OurSLAOk {
		t.Errorf("OurSLAOk = true, want false when there are no checks")
	}
}

func TestServiceHeatNil(t *testing.T) {
	if h := ServiceHeat(nil, 1, newServiceResolver(nil)); h == nil || len(h) != 0 {
		t.Errorf("ServiceHeat(nil) = %v, want empty non-nil map", h)
	}
}
