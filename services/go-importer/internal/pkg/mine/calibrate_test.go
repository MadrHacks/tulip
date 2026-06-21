package mine

import (
	"math"
	"testing"
)

func TestCalibratorLearnsChecker(t *testing.T) {
	const checker = "10.60.0.0/24"
	const attacker = "10.61.5.0/24"

	c := NewCalibrator()

	// Before enough samples: not validated, ClassifyRole fail-safes to checker.
	c.Observe(Obs{Source: checker, UnixSec: 1000, HasFlagOut: false})
	c.Observe(Obs{Source: checker, UnixSec: 1120, HasFlagOut: false})
	early := c.Model()
	if early.Validated {
		t.Fatalf("expected not validated after 2 samples")
	}
	es := early.SignalsFor(checker, false)
	if role, _ := ClassifyRole(es, early.AsModel()); role != RoleChecker {
		t.Fatalf("fail-safe before validation: want RoleChecker, got %v", role)
	}

	// Regular checker probes ~120s apart, no flag-outs (10 total).
	base := int64(1000)
	for i := 2; i < 10; i++ {
		jitter := int64((i % 3) - 1) // -1,0,1 seconds
		c.Observe(Obs{Source: checker, UnixSec: base + int64(i)*120 + jitter, HasFlagOut: false})
	}

	// Irregular attacker bursts, with flag-outs.
	for i, dt := range []int64{30, 7, 400, 12, 900, 3} {
		c.Observe(Obs{Source: attacker, UnixSec: base + dt + int64(i), HasFlagOut: true})
	}

	m := c.Model()
	if m.Source != checker {
		t.Fatalf("learned source = %q, want %q", m.Source, checker)
	}
	if !m.Validated {
		t.Fatalf("expected validated after 10 regular samples")
	}
	if math.Abs(m.PeriodSec-120) > 10 {
		t.Fatalf("PeriodSec = %v, want ~120", m.PeriodSec)
	}
	if m.Confidence <= 0 || m.Confidence > 0.95 {
		t.Fatalf("Confidence = %v out of range", m.Confidence)
	}

	// Attacker flow with flag-out -> RoleExploit.
	as := m.SignalsFor(attacker, true)
	if role, _ := ClassifyRole(as, m.AsModel()); role != RoleExploit {
		t.Fatalf("attacker flow: want RoleExploit, got %v", role)
	}

	// Checker flow -> RoleChecker.
	cs := m.SignalsFor(checker, false)
	if role, _ := ClassifyRole(cs, m.AsModel()); role != RoleChecker {
		t.Fatalf("checker flow: want RoleChecker, got %v", role)
	}

	// Snapshot/restore preserves the learned model across a restart.
	restored := restoreCalibrator(c.snapshot())
	rm := restored.Model()
	if rm.Source != m.Source || rm.Validated != m.Validated ||
		math.Abs(rm.PeriodSec-m.PeriodSec) > 1e-9 || math.Abs(rm.Confidence-m.Confidence) > 1e-9 {
		t.Fatalf("restored model %+v != original %+v", rm, m)
	}
}
