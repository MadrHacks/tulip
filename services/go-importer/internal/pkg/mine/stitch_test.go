package mine

import (
	"fmt"
	"regexp"
	"testing"

	"go-importer/internal/pkg/db"
)

// A dutyfree-style flag (matches avFlagRe [A-Z0-9]{31}=).
func stitchFlag(i int) string {
	return fmt.Sprintf("FLAGDUTYFREE%019d=", i) // 12 + 19 = 31 chars + '='
}

// bootstrapFlow is a login/GET connection that RECEIVES a session cookie: one
// client GET, one server response that Set-Cookies PHPSESSID=sess. Carries NO flag
// -- exactly the connection absent from a shape's flag-leaking members.
func bootstrapFlow(sess string) []db.Turn {
	req := "GET / HTTP/1.1\r\nHost: 10.0.0.9:6006\r\nUser-Agent: checker\r\nConnection: close\r\n\r\n"
	resp := "HTTP/1.1 200 OK\r\nConnection: close\r\nSet-Cookie: PHPSESSID=" + sess +
		"; path=/\r\nContent-Type: text/html\r\n\r\n<html>duty free</html>"
	return []db.Turn{
		{FromClient: true, Data: []byte(req)},
		{FromClient: false, Data: []byte(resp)},
	}
}

// loyaltyFlow is the exfil read on a SEPARATE connection: it PRESENTS the session
// cookie it never received here and selects an external record id -> the proven
// IDOR. The flag comes back in the response body.
func loyaltyFlow(sess, id, flag string) []db.Turn {
	req := "GET /user/loyalty?id=" + id + " HTTP/1.1\r\nHost: 10.0.0.9:6006\r\n" +
		"User-Agent: checker\r\nCookie: PHPSESSID=" + sess + "\r\nConnection: close\r\n\r\n"
	resp := "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n" +
		`{"id":"` + id + `","points":100,"flag":"` + flag + `"}`
	return []db.Turn{
		{FromClient: true, Data: []byte(req)},
		{FromClient: false, Data: []byte(resp)},
	}
}

// pathSkel is a compact structural skeleton (method + path, no query) used to
// drive the collision guard in tests.
func pathSkel(turns []db.Turn) string {
	re := regexp.MustCompile(`^(GET|POST|PUT|DELETE|HEAD|PATCH) (\S+)`)
	s := ""
	for _, t := range clientTurns(turns) {
		m := re.FindSubmatch(t)
		if m == nil {
			continue
		}
		path := m[2]
		if i := indexFrom(path, []byte("?"), 0); i >= 0 {
			path = path[:i]
		}
		s += string(m[1]) + " " + string(path) + "|"
	}
	return s
}

var stitchSessions3 = []string{
	"8h9g6teu5jcv4eds5u0h9ardcq",
	"7mno4ckcu9malr2dbc09rtcsd2",
	"87e16m5gs5st3r97mshase71mc",
}
var stitchIDs3 = []string{
	"23bdc2fe-bc85-4447-a583-ed7c2001d5a2",
	"d6edcb95-8fc7-40a1-a226-45c29eccfccf",
	"ea6321ab-0fe0-41f3-b975-1412c7c58ad8",
}

// dutyfreeCorpus builds the standalone loyalty reads (consumers) and the wider
// connection pool that also holds their bootstrap logins.
func dutyfreeCorpus() (members, pool [][]db.Turn) {
	for i := 0; i < 3; i++ {
		members = append(members, loyaltyFlow(stitchSessions3[i], stitchIDs3[i], stitchFlag(i)))
	}
	pool = append(pool, members...)
	for i := 0; i < 3; i++ {
		pool = append(pool, bootstrapFlow(stitchSessions3[i]))
	}
	return
}

// TestStitchRecoversLoyaltyIDOR is the headline case: 3 standalone
// GET /user/loyalty?id reads, each on its own connection, are stitched to the
// GET / connection that issued their PHPSESSID. The stitched shape must reproduce
// (no gate): PHPSESSID becomes a MIRROR (Set-Cookie -> Cookie) and ?id a FLAGID.
func TestStitchRecoversLoyaltyIDOR(t *testing.T) {
	members, pool := dutyfreeCorpus()

	// Sanity: unstitched, the standalone reads GATE on the external cookie.
	bare := synthesizeInteractivePlan("dutyfree", 6006, members, avFlagRe)
	if !bare.Unreproducible {
		t.Fatalf("unstitched loyalty read was NOT gated; the fixture is not exercising the gap")
	}

	stitched := stitchSessions(members, pool, nil, nil)
	if len(stitched) != 3 {
		t.Fatalf("stitched member count = %d, want 3", len(stitched))
	}
	for i, f := range stitched {
		if got := len(clientTurns(f)); got != 2 {
			t.Fatalf("stitched member %d has %d client turns, want 2 (GET / then loyalty)", i, got)
		}
	}

	plan := synthesizeInteractivePlan("dutyfree", 6006, stitched, avFlagRe)
	if plan.Unreproducible {
		t.Fatalf("stitched loyalty IDOR gated unexpectedly: %s", plan.Reason)
	}
	if len(plan.Steps) != 2 {
		t.Fatalf("steps = %d, want 2 (GET /, GET /user/loyalty?id)", len(plan.Steps))
	}

	// A MIRROR link must carry PHPSESSID from the GET / response (step 0) into the
	// loyalty request (step 1), identity transform.
	var mirror *InteractiveLink
	for i := range plan.Links {
		if plan.Links[i].Kind == "mirror" {
			mirror = &plan.Links[i]
		}
	}
	if mirror == nil {
		t.Fatalf("no MIRROR link emitted; links = %+v", plan.Links)
	}
	if mirror.ProducerStep != 0 || mirror.ConsumerStep != 1 {
		t.Errorf("mirror producer=%d consumer=%d, want 0 -> 1", mirror.ProducerStep, mirror.ConsumerStep)
	}
	if mirror.Transform != "identity" {
		t.Errorf("mirror transform = %q, want identity", mirror.Transform)
	}

	// The mirror extract must actually recover each session's PHPSESSID from its
	// GET / response, and that must be the cookie the loyalty read sent -- the
	// DERIVED (not granted) reproduction across separate connections.
	re, err := regexp.Compile(mirror.Extract)
	if err != nil {
		t.Fatalf("mirror extract regex does not compile: %v (%q)", err, mirror.Extract)
	}
	for i, f := range stitched {
		getResp := responsesPaired(f)[0]
		m := re.FindSubmatch(getResp)
		if m == nil {
			t.Fatalf("member %d: mirror extract did not match the GET / response\nregex=%q", i, mirror.Extract)
		}
		loyReq := clientTurns(f)[1]
		if !containsSub(loyReq, []byte("PHPSESSID="+string(m[1]))) {
			t.Fatalf("member %d: extracted session %q is not the cookie the loyalty read sent", i, m[1])
		}
	}

	// The loyalty step (1) must carry a FLAGID selector and a MIRROR (cookie); the
	// GET / step (0) must carry neither COMPUTED nor a gate.
	kinds := slotKinds(plan.Steps[1].Template)
	if kinds[SlotFlagID] == 0 {
		t.Errorf("loyalty step slots = %v, want a flagid selector", kinds)
	}
	if kinds[SlotMirror] == 0 {
		t.Errorf("loyalty step slots = %v, want a mirror (PHPSESSID cookie)", kinds)
	}
}

// TestStitchKeyedOnCredentialValueNotUAorIP proves the link is the credential
// VALUE: give every flow the SAME User-Agent and Host (same "UA/IP") but a
// bootstrap whose issued PHPSESSID does NOT match the read's cookie -> no stitch,
// still gated. Only a value-match stitches.
func TestStitchKeyedOnCredentialValueNotUAorIP(t *testing.T) {
	read := loyaltyFlow("MISSINGSESSIONVALUE0000000", stitchIDs3[0], stitchFlag(0))
	// Same UA / Host, but issues a DIFFERENT session value.
	wrongIssuer := bootstrapFlow("someothersessionvalue00000")
	members := [][]db.Turn{read, read, read}
	pool := [][]db.Turn{read, wrongIssuer, wrongIssuer}

	stitched := stitchSessions(members, pool, nil, nil)
	for i, f := range stitched {
		if len(clientTurns(f)) != 1 {
			t.Fatalf("member %d was stitched despite no matching credential VALUE (UA/IP must not link)", i)
		}
	}
}

// TestStitchCollisionGuardPreservesIntactShapes asserts that when the stitched
// skeleton already exists intact on a single connection (in `avoid`), the flow is
// left unstitched -- so stitched self-reads never merge into and re-label a shape
// that is already reproducing.
func TestStitchCollisionGuardPreservesIntactShapes(t *testing.T) {
	members, pool := dutyfreeCorpus()
	avoid := map[string]bool{"GET /|GET /user/loyalty|": true}

	stitched := stitchSessions(members, pool, pathSkel, avoid)
	for i, f := range stitched {
		if len(clientTurns(f)) != 1 {
			t.Fatalf("member %d was stitched into a shape already present intact (guard failed)", i)
		}
	}

	// Without the guard the same corpus stitches (regression guard on the guard).
	if got := stitchSessions(members, pool, pathSkel, nil); len(clientTurns(got[0])) != 2 {
		t.Fatalf("guard-off: expected stitch to 2 turns, got %d", len(clientTurns(got[0])))
	}
}

// TestStitchLeavesSelfIssuedSessionsUntouched asserts a same-connection session
// (cookie Set and re-presented within ONE flow) is a no-op for the stitcher --
// the already-reproducing path is never perturbed.
func TestStitchLeavesSelfIssuedSessionsUntouched(t *testing.T) {
	sess := stitchSessions3[0]
	get := "GET / HTTP/1.1\r\nHost: 10.0.0.9:6006\r\nConnection: keep-alive\r\n\r\n"
	getResp := "HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=" + sess + "; path=/\r\n\r\n<html></html>"
	loy := "GET /user/loyalty?id=" + stitchIDs3[0] + " HTTP/1.1\r\nHost: 10.0.0.9:6006\r\n" +
		"Cookie: PHPSESSID=" + sess + "\r\nConnection: close\r\n\r\n"
	loyResp := "HTTP/1.1 200 OK\r\n\r\n{\"flag\":\"" + stitchFlag(0) + "\"}"
	oneConn := []db.Turn{
		{FromClient: true, Data: []byte(get)},
		{FromClient: false, Data: []byte(getResp)},
		{FromClient: true, Data: []byte(loy)},
		{FromClient: false, Data: []byte(loyResp)},
	}
	members := [][]db.Turn{oneConn}
	// A pool that COULD issue the value externally too -- must still be a no-op,
	// because the flow already established the credential in-connection.
	pool := [][]db.Turn{oneConn, bootstrapFlow(sess)}

	if ext := externalCreds(oneConn); len(ext) != 0 {
		t.Fatalf("self-issued session reported external creds %v, want none", ext)
	}
	stitched := stitchSessions(members, pool, nil, nil)
	if len(stitched) != 1 || len(stitched[0]) != len(oneConn) {
		t.Fatalf("self-issued session was altered by stitching: %d turns (want %d)", len(stitched[0]), len(oneConn))
	}
}
