package mine

import "net/netip"

// subnet24 keys a source by its /24 (v4) or /64 (v6) so the checker calibrator
// generalizes across a source's individual hosts.
func subnet24(a netip.Addr) string {
	if a.Is4() {
		if p, err := a.Prefix(24); err == nil {
			return p.String()
		}
	} else if p, err := a.Prefix(64); err == nil {
		return p.String()
	}
	return a.String()
}

// roleTag feeds the flow to the per-service checker calibrator and returns the
// role tag the calibrated model assigns (role:checker / exploit / suspect /
// unknown). Until the model validates, everything fails safe to role:checker.
// The caller writes it together with the cluster tag in one update.
func (e *Engine) roleTag(f *Flow, service string) string {
	calib := e.calibrators[service]
	if calib == nil {
		calib = NewCalibrator()
		e.calibrators[service] = calib
	}
	src := subnet24(f.SrcIP)
	hasFlagOut := f.FlagsOut > 0
	calib.Observe(Obs{Source: src, UnixSec: f.Time.Unix(), HasFlagOut: hasFlagOut})

	model := calib.Model()
	role, _ := ClassifyRole(model.SignalsFor(src, hasFlagOut), model.AsModel())
	return "role:" + role.String()
}
