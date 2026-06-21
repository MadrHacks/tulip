package mine

// Role is the classification assigned to an observed flow.
type Role int

const (
	RoleUnknown Role = iota
	RoleChecker
	RoleExploit
	RoleSuspect
)

func (r Role) String() string {
	switch r {
	case RoleChecker:
		return "checker"
	case RoleExploit:
		return "exploit"
	case RoleSuspect:
		return "suspect"
	default:
		return "unknown"
	}
}

// Confidence levels used by ClassifyRole.
const (
	confHigh   = 0.9
	confMedium = 0.5
	confLow    = 0.2
)

// CheckerModel is filled by the separate calibration step. Validated means the
// learned source subnet/period has stabilized enough to be trusted.
type CheckerModel struct {
	Validated  bool
	Confidence float64
}

// Signals are the per-flow observations the calibrated model decides on.
type Signals struct {
	SrcInCheckerSubnet bool // flow source is in the learned checker subnet
	HasFlagOut         bool // a real flag left our box in this flow
	Periodic           bool // inter-arrival matches the learned checker cadence
}

// ClassifyRole decides the role of a flow given its signals and the calibrated
// model. When signals are weak or the model is untrusted it defaults to
// RoleChecker, the conservative choice that blocks replicate/auto-patch loops.
func ClassifyRole(s Signals, m CheckerModel) (Role, float64) {
	// 1. Fail-safe: do not act until calibration is trusted.
	if !m.Validated {
		return RoleChecker, confLow
	}

	// 2. A real flag leaving from a non-checker source is the strongest
	// attacker signal.
	if s.HasFlagOut && !s.SrcInCheckerSubnet {
		return RoleExploit, confHigh
	}

	// 3. Periodic, in-subnet, no flag out: this is the checker doing its job.
	if s.SrcInCheckerSubnet && s.Periodic && !s.HasFlagOut {
		return RoleChecker, confHigh
	}

	// 4. Conflicting: a flag left but the source looks like the checker.
	// Surface as suspect, but do not auto-act.
	if s.HasFlagOut && s.SrcInCheckerSubnet {
		return RoleSuspect, confMedium
	}

	// 5. Weak/ambiguous: conservative default.
	return RoleChecker, confLow
}
