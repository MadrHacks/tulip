package mine

import "strings"

// ServiceName strips a trailing "-<n>" port-instance suffix from a service
// shortname (the scoreboard's "CCalendar-1" -> "CCalendar"), collapsing a
// service's multiple ports to one partition key. Names without such a suffix
// are returned unchanged.
func ServiceName(shortname string) string {
	i := strings.LastIndexByte(shortname, '-')
	if i <= 0 || i == len(shortname)-1 {
		return shortname
	}
	for _, r := range shortname[i+1:] {
		if r < '0' || r > '9' {
			return shortname
		}
	}
	return shortname[:i]
}
