package mine

// Heat captures per-service signals used to prioritize offense and defense.
type Heat struct {
	OurLost     int  // flags stolen FROM our team on this service
	OurStolen   int  // flags our team stole on this service
	TotalStolen int  // flags stolen across ALL teams on this service
	OurSLAOk    bool // our team's checks all pass on this service
}

// ServiceHeat aggregates the scoreboard into per-service heat for our team. The
// resolver maps each scoreboard service name to its internal (services.yml) name
// so heat keys match the cluster shards; it is the single reconciliation point.
func ServiceHeat(sb *Scoreboard, ourTeamID int, resolver *serviceResolver) map[string]Heat {
	heat := map[string]Heat{}
	if sb == nil {
		return heat
	}

	// SLA is tracked separately so a single failing instance flips the whole
	// logical service to not-ok, and a service with no checks stays not-ok.
	slaOk := map[string]bool{}
	slaSeen := map[string]bool{}

	for _, team := range sb.Scoreboard {
		ours := team.TeamId == ourTeamID
		for _, svc := range team.Services {
			name := resolver.resolve(ServiceName(svc.Shortname))
			h := heat[name]
			h.TotalStolen += svc.Stolen
			if ours {
				h.OurLost += svc.Lost
				h.OurStolen += svc.Stolen
				instanceOk := svc.TotalChecks > 0 && svc.SuccessfulChecks == svc.TotalChecks
				if !slaSeen[name] {
					slaSeen[name] = true
					slaOk[name] = instanceOk
				} else {
					slaOk[name] = slaOk[name] && instanceOk
				}
			}
			heat[name] = h
		}
	}

	for name, ok := range slaOk {
		h := heat[name]
		h.OurSLAOk = ok
		heat[name] = h
	}

	return heat
}
