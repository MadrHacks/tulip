package mine

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Request-unit shape pipeline — stage 2: turn ONE request unit into a SKELETON
// token stream. Faithful port of stage2_normalize.py.
//
// The skeleton keeps *structure* (endpoint, method, body field-set, opcode) and
// throws away *per-instance values* (random ids, credentials, secrets, the
// flag). This is what stops reused checker secrets freezing as false constants
// and what collapses the exfil families onto one shape.
//
// HTTP unit -> tokens:
//
//	METHOD
//	path segments split on '/':
//	  - uuid / all-digits / long-random segment -> <ID>
//	  - short literal segment ("api","user",...) -> kept
//	query string: KEEP keys (sorted), MASK values -> "?k1,k2"
//	body shape: json{sorted keys} | form{sorted fields} | <MULTIPART> | <BODY>
//
// LINE unit -> tokens: OP<digit> + each whitespace-split argument masked.
//
// Value masking (applied everywhere — the rule that collapsed the exfil
// families):
//   - flag [A-Z0-9]{31}=                           -> <FLAG>
//   - [A-Za-z0-9]{8,} with >=2 distinct char-classes -> <TOK> / <ID>
//     (the char-class-count is the gate, NEVER length alone, so "checker" and
//     "products" stay literal while "WTAAvJpFPTbRQH" masks)
//   - all-digit run of len>=3 (line args)          -> <NUM>
//
// User-Agent is deliberately NOT a skeleton token — it is returned separately as
// a per-unit ANNOTATION so an actor never fragments an endpoint into per-UA
// shapes.

var (
	reUUID    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reReqLine = regexp.MustCompile(`^([A-Z]+) (\S+) HTTP/1\.[01]`)
	reUA      = regexp.MustCompile(`(?im)^user-agent:[ \t]*(.*?)\r?$`)
	reCThdr   = regexp.MustCompile(`(?im)^content-type:[ \t]*([^;\r\n]+)`)
)

// charClassCount counts how many of {lower, upper, digit} appear in s. The
// masking gate requires >= 2.
func charClassCount(s string) int {
	var lower, upper, digit bool
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	n := 0
	if lower {
		n++
	}
	if upper {
		n++
	}
	if digit {
		n++
	}
	return n
}

// isAlnumRun reports whether every rune of s is [A-Za-z0-9] (fullmatch of
// [A-Za-z0-9]{1,}); callers add the length gate.
func isAlnumRun(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// maskToken masks a single already-split token by the value rules (used for line
// arguments): flag -> <FLAG>, all-digits(>=3) -> <NUM>, long mixed-class alnum
// -> <TOK>, else literal.
func maskToken(t string) string {
	if flagShapeRe.MatchString(t) {
		return "<FLAG>"
	}
	if len(t) >= 3 && isAllDigits(t) {
		return "<NUM>"
	}
	if len(t) >= 8 && isAlnumRun(t) && charClassCount(t) >= 2 {
		return "<TOK>"
	}
	return t
}

// maskPathSeg masks one path segment: uuid / all-digits / long mixed-class alnum
// -> <ID>, else the literal is kept.
func maskPathSeg(seg string) string {
	if seg == "" {
		return seg
	}
	if reUUID.MatchString(seg) {
		return "<ID>"
	}
	if isAllDigits(seg) {
		return "<ID>"
	}
	if len(seg) >= 8 && isAlnumRun(seg) && charClassCount(seg) >= 2 {
		return "<ID>"
	}
	return seg
}

// queryKeys parses a query/form string to its sorted, de-duplicated key set,
// mirroring urllib parse_qs. keepBlank governs whether keys with an empty or
// absent value are kept (true for URL query, false for form bodies).
func queryKeys(qs string, keepBlank bool) []string {
	set := map[string]struct{}{}
	for _, pair := range strings.Split(qs, "&") {
		if pair == "" {
			continue
		}
		name := pair
		val := ""
		hasEq := false
		if idx := strings.IndexByte(pair, '='); idx >= 0 {
			name, val, hasEq = pair[:idx], pair[idx+1:], true
		}
		if !hasEq {
			if !keepBlank {
				continue
			}
		} else if val == "" && !keepBlank {
			continue
		}
		set[qsUnescape(name)] = struct{}{}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// qsUnescape decodes a query key like urllib's unquote(k.replace('+',' ')),
// falling back to a plain '+'->space swap on malformed percent-escapes.
func qsUnescape(s string) string {
	if u, err := url.QueryUnescape(s); err == nil {
		return u
	}
	return strings.ReplaceAll(s, "+", " ")
}

// bodyShape reduces a request body to its structural shape token, or "" for an
// empty body.
func bodyShape(head, body []byte) string {
	if len(bytes.TrimSpace(body)) == 0 {
		return ""
	}
	ct := ""
	if m := reCThdr.FindSubmatch(head); m != nil {
		ct = strings.ToLower(strings.TrimSpace(string(m[1])))
	}
	first := byte(0)
	if len(body) > 0 {
		first = body[0]
	}
	if strings.Contains(ct, "application/json") || first == '{' || first == '[' {
		var obj interface{}
		if err := json.Unmarshal(body, &obj); err != nil {
			return "json{?}"
		}
		if m, ok := obj.(map[string]interface{}); ok {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			return "json{" + strings.Join(keys, ",") + "}"
		}
		return "json[]"
	}
	if strings.Contains(ct, "x-www-form-urlencoded") {
		keys := queryKeys(string(body), false)
		return "form{" + strings.Join(keys, ",") + "}"
	}
	if strings.Contains(ct, "multipart/") {
		return "<MULTIPART>"
	}
	return "<BODY>"
}

// normalizeHTTP turns an HTTP request unit into its skeleton token list and its
// User-Agent annotation (empty if none). A non-HTTP first line yields
// ["<NONHTTP>"].
func normalizeHTTP(unit []byte) (toks []string, ua string) {
	he := bytes.Index(unit, crlfCRLF)
	var head, body []byte
	if he != -1 {
		head, body = unit[:he], unit[he+4:]
	} else {
		head = unit
	}
	firstLine := head
	if idx := bytes.Index(head, []byte("\r\n")); idx != -1 {
		firstLine = head[:idx]
	}
	m := reReqLine.FindSubmatch(firstLine)
	if m == nil {
		return []string{"<NONHTTP>"}, ""
	}
	method := string(m[1])
	target := string(m[2])
	path := target
	query := ""
	if idx := strings.IndexByte(target, '?'); idx != -1 {
		path, query = target[:idx], target[idx+1:]
	}
	toks = []string{method}
	for _, seg := range strings.Split(path, "/") {
		if seg == "" {
			continue
		}
		toks = append(toks, maskPathSeg(seg))
	}
	if strings.Trim(path, "/") == "" {
		toks = append(toks, "/")
	}
	if query != "" {
		keys := queryKeys(query, true)
		toks = append(toks, "?"+strings.Join(keys, ","))
	}
	if bs := bodyShape(head, body); bs != "" {
		toks = append(toks, bs)
	}
	if uam := reUA.FindSubmatch(head); uam != nil {
		ua = strings.TrimSpace(string(uam[1]))
	}
	return toks, ua
}

// normalizeLine turns a line-protocol op unit into its skeleton token list:
// OP<digit> followed by each masked whitespace-split argument.
func normalizeLine(unit []byte) (toks []string, ua string) {
	lines := bytes.Split(unit, []byte("\n"))
	op := string(bytes.TrimSpace(lines[0]))
	toks = []string{"OP" + op}
	for _, arg := range lines[1:] {
		a := string(bytes.TrimSpace(arg))
		if a == "" {
			continue
		}
		for _, piece := range strings.Fields(a) {
			toks = append(toks, maskToken(piece))
		}
	}
	return toks, ""
}

// NormalizeUnit reduces one request unit to its skeleton string (the Drain
// input) and its User-Agent annotation. An empty skeleton becomes "<EMPTY>".
func NormalizeUnit(u RequestUnit) (skeleton, userAgent string) {
	var toks []string
	if u.Proto == "http" {
		toks, userAgent = normalizeHTTP(u.Client)
	} else {
		toks, userAgent = normalizeLine(u.Client)
	}
	if len(toks) == 0 {
		return "<EMPTY>", userAgent
	}
	return strings.Join(toks, " "), userAgent
}
