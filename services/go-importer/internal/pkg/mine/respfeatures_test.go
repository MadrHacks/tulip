package mine

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"testing"
)

// dutyfree (6006) exfil response: 200 application/json, the flag hidden in a
// JSON "customization" value inside the chunked body (raw regex catches it).
const sampleFlagResp = "SFRUUC8xLjEgMjAwIE9LDQpTZXJ2ZXI6IG5naW54LzEuMjkuMQ0KRGF0ZTogRnJpLCAwMyBKdWwgMjAyNiAxMjoyOTowNCBHTVQNCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvbg0KVHJhbnNmZXItRW5jb2Rpbmc6IGNodW5rZWQNCkNvbm5lY3Rpb246IGtlZXAtYWxpdmUNCkV4cGlyZXM6IFRodSwgMTkgTm92IDE5ODEgMDg6NTI6MDAgR01UDQpDYWNoZS1Db250cm9sOiBuby1zdG9yZSwgbm8tY2FjaGUsIG11c3QtcmV2YWxpZGF0ZQ0KUHJhZ21hOiBuby1jYWNoZQ0KDQo3Nw0KW3sicHJvZHVjdF9pZCI6ImViMTVlODRlLTliN2UtNGIxMy04ZmU0LWVjNmVkYTg1NTVmOSIsInF1YW50aXR5Ijo5LCJjdXN0b21pemF0aW9uIjoiMlMxMDAzVDEyRjUyVTk1MFpBRjQwMDlLSlQ1OEQwQj0ifV0NCjANCg0K"

func TestResponseFeaturesParity(t *testing.T) {
	tests := []struct {
		name       string
		respB64    string
		wantStatus int
		wantCT     string
		wantBucket int
		wantFlag   bool
	}{
		{"flag 200 json", sampleFlagResp, 200, "application/json", 7, true},
		{"benign 302 html", sampleDutyfreeCloseResp, 302, "text/html", 5, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := ResponseFeatures(mustB64(t, tc.respB64))
			if f.HTTPStatus != tc.wantStatus {
				t.Errorf("status = %d, want %d", f.HTTPStatus, tc.wantStatus)
			}
			if f.ContentType != tc.wantCT {
				t.Errorf("content-type = %q, want %q", f.ContentType, tc.wantCT)
			}
			if f.ContentLengthBucket != tc.wantBucket {
				t.Errorf("clen bucket = %d, want %d", f.ContentLengthBucket, tc.wantBucket)
			}
			if f.FlagPresent != tc.wantFlag {
				t.Errorf("flag_present = %v, want %v", f.FlagPresent, tc.wantFlag)
			}
		})
	}
}

func TestFlowLevelFeatures(t *testing.T) {
	f := FlowLevelFeatures([]byte("some line-proto server bytes"))
	if f.ContentType != "line" || f.HTTPStatus != 0 {
		t.Errorf("line fallback = %+v", f)
	}
}

func TestResponseFeaturesEmpty(t *testing.T) {
	f := ResponseFeatures(nil)
	if f != (RespFeatures{}) {
		t.Errorf("empty response = %+v, want zero", f)
	}
}

func TestScanFlagRaw(t *testing.T) {
	if !ScanFlag([]byte("noise 2S1003T12F52U950ZAF4009KJT58D0B= tail"), 2) {
		t.Error("raw flag not found")
	}
	if ScanFlag([]byte("no flag here at all"), 2) {
		t.Error("false positive on benign data")
	}
	// depth 0 = raw only, still finds a raw flag.
	if !ScanFlag([]byte("x 2S1003T12F52U950ZAF4009KJT58D0B= y"), 0) {
		t.Error("depth-0 raw scan missed the flag")
	}
}

func TestScanFlagGzipRecursive(t *testing.T) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write([]byte(`{"loot":"2S1003T12F52U950ZAF4009KJT58D0B="}`))
	w.Close()
	if !ScanFlag(buf.Bytes(), 2) {
		t.Error("flag inside gzip not found")
	}
	if ScanFlag(buf.Bytes(), 0) {
		t.Error("depth-0 should not decode gzip")
	}
}

func TestScanFlagBase64Recursive(t *testing.T) {
	inner := []byte("prefix 2S1003T12F52U950ZAF4009KJT58D0B= suffix and more padding bytes")
	blob := base64.StdEncoding.EncodeToString(inner)
	data := []byte("some json {\"img\":\"" + blob + "\"}")
	if !ScanFlag(data, 2) {
		t.Error("flag inside base64 blob not found")
	}
}
