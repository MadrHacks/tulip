package mine

import "testing"

func TestRoleString(t *testing.T) {
	cases := []struct {
		r    Role
		want string
	}{
		{RoleUnknown, "unknown"},
		{RoleChecker, "checker"},
		{RoleExploit, "exploit"},
		{RoleSuspect, "suspect"},
		{Role(99), "unknown"},
	}
	for _, c := range cases {
		if got := c.r.String(); got != c.want {
			t.Errorf("Role(%d).String() = %q, want %q", c.r, got, c.want)
		}
	}
}

func TestClassifyRole(t *testing.T) {
	validated := CheckerModel{Validated: true, Confidence: 1}

	cases := []struct {
		name     string
		s        Signals
		m        CheckerModel
		wantRole Role
		wantConf float64
	}{
		{
			name:     "unvalidated model fail-safe",
			s:        Signals{SrcInCheckerSubnet: false, HasFlagOut: true, Periodic: false},
			m:        CheckerModel{Validated: false, Confidence: 0.99},
			wantRole: RoleChecker,
			wantConf: confLow,
		},
		{
			name:     "flag out from non-checker is exploit",
			s:        Signals{SrcInCheckerSubnet: false, HasFlagOut: true, Periodic: false},
			m:        validated,
			wantRole: RoleExploit,
			wantConf: confHigh,
		},
		{
			name:     "flag out from non-checker still exploit even if periodic",
			s:        Signals{SrcInCheckerSubnet: false, HasFlagOut: true, Periodic: true},
			m:        validated,
			wantRole: RoleExploit,
			wantConf: confHigh,
		},
		{
			name:     "periodic in-subnet no flag is checker",
			s:        Signals{SrcInCheckerSubnet: true, HasFlagOut: false, Periodic: true},
			m:        validated,
			wantRole: RoleChecker,
			wantConf: confHigh,
		},
		{
			name:     "conflicting flag out in subnet is suspect",
			s:        Signals{SrcInCheckerSubnet: true, HasFlagOut: true, Periodic: false},
			m:        validated,
			wantRole: RoleSuspect,
			wantConf: confMedium,
		},
		{
			name:     "conflicting flag out in subnet periodic is still suspect",
			s:        Signals{SrcInCheckerSubnet: true, HasFlagOut: true, Periodic: true},
			m:        validated,
			wantRole: RoleSuspect,
			wantConf: confMedium,
		},
		{
			name:     "in-subnet not periodic no flag is ambiguous checker default",
			s:        Signals{SrcInCheckerSubnet: true, HasFlagOut: false, Periodic: false},
			m:        validated,
			wantRole: RoleChecker,
			wantConf: confLow,
		},
		{
			name:     "non-checker not periodic no flag is ambiguous checker default",
			s:        Signals{SrcInCheckerSubnet: false, HasFlagOut: false, Periodic: false},
			m:        validated,
			wantRole: RoleChecker,
			wantConf: confLow,
		},
		{
			name:     "non-checker periodic no flag is ambiguous checker default",
			s:        Signals{SrcInCheckerSubnet: false, HasFlagOut: false, Periodic: true},
			m:        validated,
			wantRole: RoleChecker,
			wantConf: confLow,
		},
		{
			name:     "all signals true validated is suspect (flag out in subnet)",
			s:        Signals{SrcInCheckerSubnet: true, HasFlagOut: true, Periodic: true},
			m:        validated,
			wantRole: RoleSuspect,
			wantConf: confMedium,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotRole, gotConf := ClassifyRole(c.s, c.m)
			if gotRole != c.wantRole {
				t.Errorf("role = %v, want %v", gotRole, c.wantRole)
			}
			if gotConf != c.wantConf {
				t.Errorf("conf = %v, want %v", gotConf, c.wantConf)
			}
			if gotConf < 0 || gotConf > 1 {
				t.Errorf("conf %v out of [0,1]", gotConf)
			}
		})
	}
}

// TestExploitInvariant asserts the safety property: nothing is RoleExploit
// unless there is a real flag-out from a non-checker source AND the model is
// validated.
func TestExploitInvariant(t *testing.T) {
	for _, validated := range []bool{false, true} {
		for i := 0; i < 8; i++ {
			s := Signals{
				SrcInCheckerSubnet: i&1 != 0,
				HasFlagOut:         i&2 != 0,
				Periodic:           i&4 != 0,
			}
			m := CheckerModel{Validated: validated, Confidence: 1}
			role, _ := ClassifyRole(s, m)
			if role == RoleExploit {
				if !(validated && s.HasFlagOut && !s.SrcInCheckerSubnet) {
					t.Errorf("RoleExploit returned without (validated && flag-out && non-checker): validated=%v signals=%+v", validated, s)
				}
			}
		}
	}
}
