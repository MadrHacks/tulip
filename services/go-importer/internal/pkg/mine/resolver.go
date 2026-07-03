package mine

import (
	"strings"

	"go-importer/internal/pkg/config"
)

// serviceResolver reconciles the scoreboard's service names with the internal
// (services.yml / vulnbox-folder) names. These come from independent sources and
// routinely differ in capitalization and separators, so the default is a fuzzy
// match; a service may pin it with an explicit scoreboard_name.
//
// This is the ONLY place service-name fuzzy matching happens. Every other part of
// the system uses the exact internal name, so the reconciliation is not repeated.
type serviceResolver struct {
	exact  map[string]string // explicit scoreboard_name -> internal name
	folded map[string]string // folded internal name -> internal name
}

func newServiceResolver(defs []config.ServiceDef) *serviceResolver {
	r := &serviceResolver{exact: map[string]string{}, folded: map[string]string{}}
	for _, d := range defs {
		if d.ScoreboardName != "" {
			r.exact[d.ScoreboardName] = d.Name
		}
		r.folded[foldServiceName(d.Name)] = d.Name
	}
	return r
}

// foldServiceName is the single canonical form used for fuzzy matching: lowercase
// with every non-alphanumeric character dropped, so "Control Tower", "control-tower"
// and "controltower" all fold together.
func foldServiceName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// resolve maps a scoreboard service name to the internal name: an explicit
// scoreboard_name override wins, then a folded match, else the name is returned
// unchanged (a true miss that the detect boundary check surfaces).
func (r *serviceResolver) resolve(scoreboardName string) string {
	if n, ok := r.exact[scoreboardName]; ok {
		return n
	}
	if n, ok := r.folded[foldServiceName(scoreboardName)]; ok {
		return n
	}
	return scoreboardName
}
