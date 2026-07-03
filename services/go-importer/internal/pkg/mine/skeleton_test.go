package mine

import (
	"reflect"
	"testing"
)

// TestNormalizeUnitParity asserts the Go skeletons match, token-for-token, what
// the Python prototype produced on the same real client streams (see the base64
// samples and prototype outputs in segment_test.go / extraction).
func TestNormalizeUnitParity(t *testing.T) {
	tests := []struct {
		name      string
		svc       string
		port      int
		clientB64 string
		wantSkel  []string
		wantUA    []string
	}{
		{
			name:      "boomthrow pipelined",
			svc:       "boomthrow",
			port:      8080,
			clientB64: sampleBoomthrowClient,
			wantSkel: []string{
				"POST api register json{full_name,password,username}",
				"POST api login json{password,username}",
				"GET api qr ?id,sig",
			},
			wantUA: []string{"checker", "checker", "python-urllib3/2.7.0"},
		},
		{
			name:      "dutyfree query",
			svc:       "dutyfree",
			port:      6006,
			clientB64: sampleDutyfreeQueryClient,
			wantSkel:  []string{"GET product ?id"},
			wantUA:    []string{"checker"},
		},
		{
			name:      "skypedia line ops",
			svc:       "skypedia",
			port:      1337,
			clientB64: sampleSkypediaLineClient,
			wantSkel: []string{
				"OP1 <TOK> <TOK>",
				"OP2 <TOK> <TOK>",
				"OP1 <TOK> <TOK>",
				"OP6 <TOK>",
			},
			wantUA: []string{"", "", "", ""},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := mustB64(t, tc.clientB64)
			fl := SegmentFlow("f", tc.svc, tc.port, false, false, client, nil)
			if len(fl.Units) != len(tc.wantSkel) {
				t.Fatalf("units = %d, want %d", len(fl.Units), len(tc.wantSkel))
			}
			for i, u := range fl.Units {
				sk, ua := NormalizeUnit(u)
				if sk != tc.wantSkel[i] {
					t.Errorf("unit %d skeleton = %q, want %q", i, sk, tc.wantSkel[i])
				}
				if ua != tc.wantUA[i] {
					t.Errorf("unit %d ua = %q, want %q", i, ua, tc.wantUA[i])
				}
			}
		})
	}
}

func TestMaskPathSeg(t *testing.T) {
	cases := map[string]string{
		"api":                                  "api",      // short literal kept
		"products":                             "products", // len>=8 but one class -> kept
		"checker":                              "checker",  // len<8 -> kept
		"12345":                                "<ID>",     // all digits
		"a6f9999e-33af-4ddc-866a-09d474539aec": "<ID>",     // uuid
		"WTAAvJpFPTbRQH":                       "<ID>",     // long, >=2 char classes
	}
	for in, want := range cases {
		if got := maskPathSeg(in); got != want {
			t.Errorf("maskPathSeg(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskToken(t *testing.T) {
	cases := map[string]string{
		"2S1003T12F52U950ZAF4009KJT58D0B=": "<FLAG>",   // 31 upper-alnum + '='
		"123":                              "<NUM>",    // all-digit run >=3
		"12":                               "12",       // too short for <NUM>
		"aaa":                              "aaa",      // lowercase word, one class
		"WW7KTDHJZDEP3T9J":                 "<TOK>",    // long, upper+digit
		"products":                         "products", // one class -> literal
	}
	for in, want := range cases {
		if got := maskToken(in); got != want {
			t.Errorf("maskToken(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestQueryKeys(t *testing.T) {
	if got := queryKeys("id=x&sig=y", true); !reflect.DeepEqual(got, []string{"id", "sig"}) {
		t.Errorf("query keys = %v", got)
	}
	// keep-blank governs bare/empty-valued keys (URL query vs form body).
	if got := queryKeys("tag", true); !reflect.DeepEqual(got, []string{"tag"}) {
		t.Errorf("keepBlank bare key = %v, want [tag]", got)
	}
	if got := queryKeys("tag", false); len(got) != 0 {
		t.Errorf("no-keepBlank bare key = %v, want empty", got)
	}
	// sorted + de-duplicated
	if got := queryKeys("b=1&a=2&b=3", true); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("dedup/sort = %v", got)
	}
}

func TestBodyShape(t *testing.T) {
	head := []byte("POST /x HTTP/1.1\r\nContent-Type: application/json\r\n")
	if got := bodyShape(head, []byte(`{"b":1,"a":2}`)); got != "json{a,b}" {
		t.Errorf("json body shape = %q", got)
	}
	if got := bodyShape(head, []byte(`[1,2,3]`)); got != "json[]" {
		t.Errorf("json array shape = %q", got)
	}
	formHead := []byte("POST /x HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n")
	if got := bodyShape(formHead, []byte("password=p&username=u")); got != "form{password,username}" {
		t.Errorf("form body shape = %q", got)
	}
	mpHead := []byte("POST /x HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=z\r\n")
	if got := bodyShape(mpHead, []byte("--z\r\n...")); got != "<MULTIPART>" {
		t.Errorf("multipart shape = %q", got)
	}
	if got := bodyShape(head, []byte("   ")); got != "" {
		t.Errorf("empty body shape = %q, want empty", got)
	}
}
