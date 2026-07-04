package mine

// Cross-connection SESSION STITCHING, ported faithfully from the validated
// reference (scratchpad/repro-engine: loaders.stitch_sessions).
//
// Cookie/token-auth services routinely split one logical SESSION across separate
// TCP connections: the login that RECEIVES `Set-Cookie: PHPSESSID=V` (or a JWT in
// the response body) is one connection; the exfil read that SENDS `Cookie:
// PHPSESSID=V` (or `Authorization: Bearer V`) is another. In the second
// connection there is no in-session Set-Cookie to mirror, so the credential slot
// is an unreconstructable EXTERNAL session token -> the whole plan GATES.
//
// Stitch them by the shared concrete credential VALUE V: a flow whose RESPONSE
// issued V and a flow whose REQUEST presents V are the SAME logical session ->
// concatenate (issuer turns, then consumer turns). V then becomes an in-session
// Set-Cookie->Cookie (or response-body->Authorization) MIRROR, exactly like the
// same-connection case that already reproduces. The link is the credential VALUE
// ONLY -- never User-Agent / IP, which are NOT session identity and must never be
// grouping keys.
//
// This is a PURE primitive over ordered turns: it takes the shape's member flows
// plus an issuer-candidate `pool` and returns the (possibly stitched) members to
// hand to analyseShape. It reads nothing from the DB itself; the caller supplies
// the candidate pool (the login/bootstrap connections carry no flag, so they are
// absent from a shape's flag-leaking members and must come from a wider pool).

import (
	"bytes"
	"regexp"

	"go-importer/internal/pkg/db"
)

const stitchMinLen = 8 // a session credential value must be at least this long to link on

var (
	reSetCookie = regexp.MustCompile(`(?im)^Set-Cookie:\s*([A-Za-z0-9_.-]+)=([^;\r\n]+)`)
	reCookieReq = regexp.MustCompile(`(?im)^Cookie:\s*([^\r\n]+)`)
	reBearerReq = regexp.MustCompile(`(?im)^Authorization:\s*(?:Bearer|Token)\s+([^\r\n]+)`)
	reBodyToken = regexp.MustCompile(`(?i)"(?:token|jwt|access_token|auth|session|sessionid|sid)"\s*:\s*"([^"\\]{8,})"`)
)

// issuedCreds is the set of credential VALUES a flow's server RESPONSES hand back
// to the client: Set-Cookie values and response-body token fields.
func issuedCreds(turns []db.Turn) map[string]bool {
	out := map[string]bool{}
	for _, t := range turns {
		if t.FromClient {
			continue
		}
		for _, m := range reSetCookie.FindAllSubmatch(t.Data, -1) {
			if v := bytes.TrimSpace(m[2]); len(v) >= stitchMinLen {
				out[string(v)] = true
			}
		}
		for _, m := range reBodyToken.FindAllSubmatch(t.Data, -1) {
			if v := bytes.TrimSpace(m[1]); len(v) >= stitchMinLen {
				out[string(v)] = true
			}
		}
	}
	return out
}

// requestCredsIn is the credential VALUES a single client request presents
// (Cookie values + a Bearer/Token authorization), each at least stitchMinLen long.
func requestCredsIn(req []byte) [][]byte {
	var vals [][]byte
	for _, m := range reCookieReq.FindAllSubmatch(req, -1) {
		for _, kv := range bytes.Split(m[1], []byte(";")) {
			if i := bytes.IndexByte(kv, '='); i >= 0 {
				vals = append(vals, bytes.TrimSpace(kv[i+1:]))
			}
		}
	}
	if m := reBearerReq.FindSubmatch(req); m != nil {
		vals = append(vals, bytes.TrimSpace(m[1]))
	}
	out := vals[:0]
	for _, v := range vals {
		if len(v) >= stitchMinLen {
			out = append(out, v)
		}
	}
	return out
}

// externalCreds is the credential VALUES a flow PRESENTS in a request but did NOT
// itself receive in an earlier response of the SAME connection -> it needs an
// external issuer to become a reconstructable in-session mirror. A flow that
// established its own credential in-connection (the already-reproducing same-
// connection case) yields none, so stitching leaves it untouched.
func externalCreds(turns []db.Turn) []string {
	issued := map[string]bool{}
	var need []string
	for _, t := range turns {
		if !t.FromClient {
			for _, m := range reSetCookie.FindAllSubmatch(t.Data, -1) {
				issued[string(bytes.TrimSpace(m[2]))] = true
			}
			for _, m := range reBodyToken.FindAllSubmatch(t.Data, -1) {
				issued[string(bytes.TrimSpace(m[1]))] = true
			}
			continue
		}
		for _, v := range requestCredsIn(t.Data) {
			if !issued[string(v)] {
				need = append(need, string(v))
			}
		}
	}
	return need
}

// sameFlow reports whether two member slices alias the same backing turns (the Go
// analogue of the reference's `candidate is not consumer` identity check).
func sameFlow(a, b []db.Turn) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}

// stitchSessions returns `flows` with every flow that presents an EXTERNAL session
// credential replaced by [issuer.turns + flow.turns], where `issuer` is a flow
// from `pool` (default `flows`) whose response issued that exact credential VALUE.
// Same-connection sessions (credential self-issued) are returned unchanged, so a
// shape that already reproduces on its own is never perturbed.
//
// Stitching is used only to RECOVER a shape not already observed intact on a
// single connection: when `skelFn`/`avoid` are supplied and the stitched session's
// skeleton is already present in `avoid` (the same-connection shapes), the flow is
// left unstitched -- that keeps stitched self-reads from merging into, and
// re-labelling, a shape that is already reproducing. Pass a nil `avoid` to stitch
// unconditionally.
func stitchSessions(flows, pool [][]db.Turn, skelFn func([]db.Turn) string, avoid map[string]bool) [][]db.Turn {
	if pool == nil {
		pool = flows
	}
	issuers := map[string][]int{}
	for pi, f := range pool {
		for v := range issuedCreds(f) {
			issuers[v] = append(issuers[v], pi)
		}
	}
	needExtCache := map[int]int{} // pool index -> -1 unknown, 0 no, 1 yes
	needsExternal := func(pi int) bool {
		if b, ok := needExtCache[pi]; ok {
			return b == 1
		}
		b := 0
		if len(externalCreds(pool[pi])) > 0 {
			b = 1
		}
		needExtCache[pi] = b
		return b == 1
	}
	clientTurnCount := func(f []db.Turn) int {
		n := 0
		for _, t := range f {
			if t.FromClient {
				n++
			}
		}
		return n
	}
	out := make([][]db.Turn, 0, len(flows))
	for _, f := range flows {
		chosen := -1
		for _, v := range externalCreds(f) {
			// Prefer the cleanest bootstrap: a self-contained issuer (needs no
			// external cred of its own) with the fewest client turns; first in pool
			// order breaks ties -- deterministic.
			best := -1
			for _, pi := range issuers[v] {
				if sameFlow(pool[pi], f) {
					continue
				}
				if best < 0 {
					best = pi
					continue
				}
				bn, cn := needsExternal(best), needsExternal(pi)
				if (cn != bn && !cn) || (cn == bn && clientTurnCount(pool[pi]) < clientTurnCount(pool[best])) {
					best = pi
				}
			}
			if best >= 0 {
				chosen = best
				break
			}
		}
		if chosen < 0 {
			out = append(out, f)
			continue
		}
		st := make([]db.Turn, 0, len(pool[chosen])+len(f))
		st = append(st, pool[chosen]...)
		st = append(st, f...)
		if skelFn != nil && avoid != nil && avoid[skelFn(st)] {
			out = append(out, f) // this shape already exists intact -> don't merge into it
			continue
		}
		out = append(out, st)
	}
	return out
}
