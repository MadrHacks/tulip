package mine

import (
	"bytes"
	"encoding/base64"
	"testing"

	"go-importer/internal/pkg/db"
)

// Real preserved-dataset samples (base64 of the decoded client/server bytes),
// captured together with the Python prototype's own segmentation/skeleton
// outputs so these tests assert Go/Python parity on genuine traffic.

// boomthrow (8080) pipelined keep-alive flow: register(JSON body) glued to
// login(JSON body) glued to GET /api/qr — the length-aware split must find all
// three despite bodies gluing to the next request line.
const sampleBoomthrowClient = "UE9TVCAvYXBpL3JlZ2lzdGVyIEhUVFAvMS4xDQpIb3N0OiAxMC42MC4zNi4xOjgwODANClVzZXItQWdlbnQ6IGNoZWNrZXINCkFjY2VwdC1FbmNvZGluZzogZ3ppcCwgZGVmbGF0ZQ0KQWNjZXB0OiAqLyoNCkNvbm5lY3Rpb246IGtlZXAtYWxpdmUNCkNvbnRlbnQtTGVuZ3RoOiA4NA0KQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi9qc29uDQoNCnsiZnVsbF9uYW1lIjogIk1qaGlqSVNxS1ZaeVpPbCIsICJ1c2VybmFtZSI6ICJTN0NseVBWR0FsIiwgInBhc3N3b3JkIjogInFrM2trQzVnTE8ifVBPU1QgL2FwaS9sb2dpbiBIVFRQLzEuMQ0KSG9zdDogMTAuNjAuMzYuMTo4MDgwDQpVc2VyLUFnZW50OiBjaGVja2VyDQpBY2NlcHQtRW5jb2Rpbmc6IGd6aXAsIGRlZmxhdGUNCkFjY2VwdDogKi8qDQpDb25uZWN0aW9uOiBrZWVwLWFsaXZlDQpDb250ZW50LUxlbmd0aDogNTINCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvbg0KDQp7InVzZXJuYW1lIjogIlM3Q2x5UFZHQWwiLCAicGFzc3dvcmQiOiAicWsza2tDNWdMTyJ9R0VUIC9hcGkvcXI/aWQ9ZDdhZTRhYWQtYzEzYS00NTBkLWI5MjQtZjI5YmE5NjYxMWFkJnNpZz01YjIzMjkzNTI4ZDcyMmUyYmIwMDliZjMzM2RmNWQ5ZCBIVFRQLzEuMQ0KSG9zdDogMTAuNjAuMzYuMTo4MDgwDQpBY2NlcHQtRW5jb2Rpbmc6IGlkZW50aXR5DQpVc2VyLUFnZW50OiBweXRob24tdXJsbGliMy8yLjcuMA0KQXV0aG9yaXphdGlvbjogQmVhcmVyIEg0c0lBQTZyUjJvQ193czJkODZwREFoemQ4eGhJQV80Wm1Wa1pua0dGM3FIUlZWRy1aTnJ5dkFGWEx3YWYxUmZ2NHpkdjE1RzhhWkVKZU90WU12elBmZmlmOFF3TEEyU3VSZHlGQUROWWtHcmdSRUFBQT09DQoNCg=="

// skypedia (1337) line/menu protocol: opcode digit lines 1/2/1/6 each followed
// by their argument lines.
const sampleSkypediaLineClient = "MQo1MllpWkYyYzFJbk5kSmF1Y044eApBODBJOHU5dmtuUExlWTIKMgo1MllpWkYyYzFJbk5kSmF1Y044eApBODBJOHU5dmtuUExlWTIKMQpzZkZsNmlWNE40U0s4SG00eWhTZk1nQWc1awpuc1NhR3J5VVRGZE1DS1cKNgpXVzdLVERISlpERVAzVDlKCg=="

// dutyfree (6006) single GET /product?id=<uuid> request (query key kept, value
// masked).
const sampleDutyfreeQueryClient = "R0VUIC9wcm9kdWN0P2lkPWE2Zjk5OTllLTMzYWYtNGRkYy04NjZhLTA5ZDQ3NDUzOWFlYyBIVFRQLzEuMQ0KSG9zdDogMTAuNjAuMzYuMTo2MDA2DQpVc2VyLUFnZW50OiBjaGVja2VyDQpBY2NlcHQtRW5jb2Rpbmc6IGd6aXAsIGRlZmxhdGUNCkFjY2VwdDogKi8qDQpDb25uZWN0aW9uOiBjbG9zZQ0KQ29va2llOiBQSFBTRVNTSUQ9dWl1aDQ3dGhzcWh0cG1pdjBmZ2pqMWlhY2cNCg0K"

// dutyfree (6006) chunked text/html response with Connection: close (a benign
// 302 redirect).
const sampleDutyfreeCloseResp = "SFRUUC8xLjEgMzAyIEZvdW5kDQpTZXJ2ZXI6IG5naW54LzEuMjkuMQ0KRGF0ZTogRnJpLCAwMyBKdWwgMjAyNiAxMjoyOTozMiBHTVQNCkNvbnRlbnQtVHlwZTogdGV4dC9odG1sOyBjaGFyc2V0PVVURi04DQpUcmFuc2Zlci1FbmNvZGluZzogY2h1bmtlZA0KQ29ubmVjdGlvbjogY2xvc2UNClNldC1Db29raWU6IFBIUFNFU1NJRD1uYmFvaGMybTJidjZ1dTRsaWFmbGgzb2U4NzsgcGF0aD0vDQpFeHBpcmVzOiBUaHUsIDE5IE5vdiAxOTgxIDA4OjUyOjAwIEdNVA0KQ2FjaGUtQ29udHJvbDogbm8tc3RvcmUsIG5vLWNhY2hlLCBtdXN0LXJldmFsaWRhdGUNClByYWdtYTogbm8tY2FjaGUNCkxvY2F0aW9uOiAvDQoNCjI0DQo0NjVhNTFlZi1mM2NlLTQ1MDEtYjU2MC0zZmQ0YTQyN2Q4YTQNCjANCg0K"

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	return b
}

func TestSegmentHTTPPipelinedSplitsGluedBodies(t *testing.T) {
	client := mustB64(t, sampleBoomthrowClient)
	fl := SegmentFlow("f", "boomthrow", 8080, false, false, client, nil)
	if fl.Proto != "http" {
		t.Fatalf("proto = %q, want http", fl.Proto)
	}
	if len(fl.Units) != 3 {
		t.Fatalf("units = %d, want 3", len(fl.Units))
	}
	// Each unit must begin at a request line (bodies were consumed by length).
	wantStart := []string{"POST /api/register", "POST /api/login", "GET /api/qr"}
	for i, w := range wantStart {
		got := string(fl.Units[i].Client)
		if len(got) < len(w) || got[:len(w)] != w {
			t.Errorf("unit %d does not start with %q", i, w)
		}
	}
}

func TestSegmentLineOpsSplitsOnOpcodes(t *testing.T) {
	client := mustB64(t, sampleSkypediaLineClient)
	fl := SegmentFlow("f", "skypedia", 1337, false, false, client, nil)
	if fl.Proto != "line" {
		t.Fatalf("proto = %q, want line", fl.Proto)
	}
	if len(fl.Units) != 4 {
		t.Fatalf("units = %d, want 4", len(fl.Units))
	}
	// Each unit's first line is its opcode.
	wantOps := []string{"1", "2", "1", "6"}
	for i, w := range wantOps {
		first := firstLine(fl.Units[i].Client)
		if first != w {
			t.Errorf("unit %d opcode = %q, want %q", i, first, w)
		}
	}
	// Line units carry no per-op response.
	for i, u := range fl.Units {
		if u.Response != nil {
			t.Errorf("unit %d has non-nil response", i)
		}
	}
}

func TestSegmentResponseConnCloseChunked(t *testing.T) {
	resp := mustB64(t, sampleDutyfreeCloseResp)
	units := splitHTTPResponses(resp)
	if len(units) != 1 {
		t.Fatalf("response units = %d, want 1", len(units))
	}
	if len(units[0]) != len(resp) {
		t.Errorf("response unit len = %d, want whole stream %d", len(units[0]), len(resp))
	}
}

func TestSegmentContentLengthConsumesExactBody(t *testing.T) {
	// Two pipelined POSTs; the first body (len 5) must not bleed into the second.
	raw := "POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloPOST /b HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
	units := splitHTTPRequests([]byte(raw))
	if len(units) != 2 {
		t.Fatalf("units = %d, want 2", len(units))
	}
	if got := string(units[0]); got != "POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello" {
		t.Errorf("unit0 = %q", got)
	}
	if got := string(units[1]); got != "POST /b HTTP/1.1\r\nContent-Length: 0\r\n\r\n" {
		t.Errorf("unit1 = %q", got)
	}
}

// TestSegmentMessagesHTTPPairsFollowingResponse: on an ordered keep-alive
// conversation (C1 S1 C2 S2), each request pairs with the response that ACTUALLY
// followed it — GET /a with the 200, GET /b with the 404 — proving the true
// alternation, not a by-global-index guess.
func TestSegmentMessagesHTTPPairsFollowingResponse(t *testing.T) {
	msgs := []db.FlowMessage{
		{FromClient: true, Data: []byte("GET /a HTTP/1.1\r\nHost: t\r\n\r\n")},
		{FromClient: false, Data: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nAA")},
		{FromClient: true, Data: []byte("GET /b HTTP/1.1\r\nHost: t\r\n\r\n")},
		{FromClient: false, Data: []byte("HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nBBB")},
	}
	units := SegmentMessages(msgs)
	if len(units) != 2 {
		t.Fatalf("units = %d, want 2", len(units))
	}
	if units[0].Proto != "http" {
		t.Fatalf("proto = %q, want http", units[0].Proto)
	}
	if !bytes.HasPrefix(units[0].Client, []byte("GET /a")) {
		t.Errorf("unit0 client = %q, want GET /a", units[0].Client)
	}
	if !bytes.Contains(units[0].Response, []byte("200 OK")) {
		t.Errorf("unit0 response = %q, want the 200 that followed GET /a", units[0].Response)
	}
	if !bytes.HasPrefix(units[1].Client, []byte("GET /b")) {
		t.Errorf("unit1 client = %q, want GET /b", units[1].Client)
	}
	if !bytes.Contains(units[1].Response, []byte("404 Not Found")) {
		t.Errorf("unit1 response = %q, want the 404 that followed GET /b", units[1].Response)
	}
}

// TestSegmentMessagesLinePairsPerOpResponse: on an interactive 1337 op sequence
// (C op1, S resp1, C op2, S resp2), each op pairs with its own response — the
// per-op pairing the concatenated-stream SegmentFlow could not recover (it
// leaves line responses nil).
func TestSegmentMessagesLinePairsPerOpResponse(t *testing.T) {
	msgs := []db.FlowMessage{
		{FromClient: true, Data: []byte("1\nWTAAvJpFPTbRQH\n")},
		{FromClient: false, Data: []byte("ok: created id 7\n")},
		{FromClient: true, Data: []byte("2\n7\n")},
		{FromClient: false, Data: []byte("value: hello\n")},
	}
	units := SegmentMessages(msgs)
	if len(units) != 2 {
		t.Fatalf("units = %d, want 2", len(units))
	}
	if units[0].Proto != "line" {
		t.Fatalf("proto = %q, want line", units[0].Proto)
	}
	if got := firstLine(units[0].Client); got != "1" {
		t.Errorf("unit0 opcode = %q, want 1", got)
	}
	if string(units[0].Response) != "ok: created id 7\n" {
		t.Errorf("unit0 response = %q, want the reply that followed op 1", units[0].Response)
	}
	if got := firstLine(units[1].Client); got != "2" {
		t.Errorf("unit1 opcode = %q, want 2", got)
	}
	if string(units[1].Response) != "value: hello\n" {
		t.Errorf("unit1 response = %q, want the reply that followed op 2", units[1].Response)
	}
}

func firstLine(b []byte) string {
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' || b[i] == '\r' {
			return string(b[:i])
		}
	}
	return string(b)
}
