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

// canonical returns the unmasked canonical request (HTTP structural form, or the
// raw bytes for non-HTTP). Template synthesis diffs cluster members on this.
func canonical(clientData []byte) []byte {
	if canon, ok := httpRequestCanon(clientData); ok {
		return canon
	}
	return clientData
}

// Normalize returns the masked canonical request for clustering.
func Normalize(clientData []byte, flagRe, fidRe *regexp.Regexp) []byte {
	return maskValues(canonical(clientData), flagRe, fidRe)
}

// maskValues replaces flag and flagId occurrences with sentinels in a single
// pass each. fidRe is a precompiled alternation of the live flagIds (built once
// per refresh), so masking is O(payload), not O(payload * #flagIds).
func maskValues(data []byte, flagRe, fidRe *regexp.Regexp) []byte {
	if flagRe != nil {
		data = flagRe.ReplaceAll(data, flagSentinel)
	}
	if fidRe != nil {
		data = fidRe.ReplaceAll(data, fidSentinel)
	}
	return data
}

// buildFlagIDRegex compiles the live flagIds into one alternation matcher, with
// longer ids first so an id containing another is masked whole. Returns nil when
// there is nothing maskable.
func buildFlagIDRegex(flagIDs []string) *regexp.Regexp {
	parts := make([]string, 0, len(flagIDs))
	for _, id := range flagIDs {
		if len(id) >= minMaskLen {
			parts = append(parts, regexp.QuoteMeta(id))
		}
	}
	if len(parts) == 0 {
		return nil
	}
	sort.Slice(parts, func(i, j int) bool { return len(parts[i]) > len(parts[j]) })
	re, err := regexp.Compile(strings.Join(parts, "|"))
	if err != nil {
		return nil
	}
	return re
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
