package mine

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// Request normalization: reduce a flow's client-side bytes to the canonical
// representation it clusters on. For HTTP this is method + path-template +
// sorted query + stable headers + body; non-HTTP payloads pass through. Flag and
// flagId values are masked to sentinels AFTER parsing (so they cannot perturb
// Content-Length), collapsing otherwise-unique attack requests onto one shape.

var (
	flagSentinel = []byte("\x00F\x00")
	fidSentinel  = []byte("\x00I\x00")
)

const minMaskLen = 4

var volatileHeaders = map[string]bool{
	"Date": true, "Cookie": true, "Set-Cookie": true, "User-Agent": true,
	"Host": true, "Connection": true, "Content-Length": true, "Accept": true,
	"Accept-Encoding": true, "Accept-Language": true, "Cache-Control": true,
	"Pragma": true, "Referer": true, "Origin": true, "Te": true,
	"Upgrade-Insecure-Requests": true,
}

// Normalize returns the masked canonical request for clustering.
func Normalize(clientData []byte, flagRe *regexp.Regexp, flagIDs []string) []byte {
	if canon, ok := httpRequestCanon(clientData); ok {
		return maskValues(canon, flagRe, flagIDs)
	}
	return maskValues(clientData, flagRe, flagIDs)
}

func maskValues(data []byte, flagRe *regexp.Regexp, flagIDs []string) []byte {
	if flagRe != nil {
		data = flagRe.ReplaceAll(data, flagSentinel)
	}
	for _, id := range flagIDs {
		if len(id) >= minMaskLen {
			data = bytes.ReplaceAll(data, []byte(id), fidSentinel)
		}
	}
	return data
}

func httpRequestCanon(data []byte) ([]byte, bool) {
	r := bufio.NewReader(bytes.NewReader(data))
	var out []byte
	for i := 0; i < 8; i++ {
		req, err := http.ReadRequest(r)
		if err != nil {
			break
		}
		out = append(out, requestCanon(req)...)
		out = append(out, '\n')
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func requestCanon(req *http.Request) []byte {
	var b strings.Builder
	b.WriteString(req.Method)
	b.WriteByte(' ')
	b.WriteString(pathTemplate(req.URL.Path))

	query := req.URL.Query()
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		values := append([]string(nil), query[k]...)
		sort.Strings(values)
		for _, v := range values {
			b.WriteByte(' ')
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(v)
		}
	}
	b.WriteByte('\n')

	headers := make([]string, 0, len(req.Header))
	for k := range req.Header {
		if !volatileHeaders[http.CanonicalHeaderKey(k)] {
			headers = append(headers, k)
		}
	}
	sort.Strings(headers)
	for _, k := range headers {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(strings.Join(req.Header[k], ","))
		b.WriteByte('\n')
	}

	if req.Body != nil {
		body, _ := io.ReadAll(io.LimitReader(req.Body, 64*1024))
		b.Write(body)
	}
	return []byte(b.String())
}

func pathTemplate(path string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if isVariableSeg(s) {
			segs[i] = "{}"
		}
	}
	return strings.Join(segs, "/")
}

func isVariableSeg(s string) bool {
	if len(s) == 0 {
		return false
	}
	if len(s) > 16 {
		return true
	}
	allDigit, allHex := true, true
	for _, r := range s {
		if r < '0' || r > '9' {
			allDigit = false
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			allHex = false
		}
	}
	return allDigit || (allHex && len(s) >= 8)
}
