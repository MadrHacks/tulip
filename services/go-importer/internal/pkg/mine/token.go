package mine

import "math"

// Token thresholds for the high-entropy-token (HET) gate.
const (
	tokenMinLen     = 8
	tokenMaxLen     = 512
	tokenMinEntropy = 3.0
)

// Charclass classifies the character alphabet of a token, from most specific
// (structurally typed) to least.
type Charclass int

// Charclass values, ordered most-specific first.
const (
	ClassOther Charclass = iota
	ClassHex
	ClassBase64
	ClassBase64URL
	ClassUUID
	ClassJWT
	ClassAlnum
)

// String returns the canonical name of the charclass.
func (c Charclass) String() string {
	switch c {
	case ClassHex:
		return "hex"
	case ClassBase64:
		return "base64"
	case ClassBase64URL:
		return "base64url"
	case ClassUUID:
		return "uuid"
	case ClassJWT:
		return "jwt"
	case ClassAlnum:
		return "alnum"
	default:
		return "other"
	}
}

// DetectCharclass returns the most specific charclass matching s, checking
// structural types (UUID, JWT) before alphabet-based ones.
func DetectCharclass(s []byte) Charclass {
	if len(s) == 0 {
		return ClassOther
	}
	if isUUID(s) {
		return ClassUUID
	}
	if isJWT(s) {
		return ClassJWT
	}
	return classifyAlphabet(s)
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isAlnumByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// classifyAlphabet picks the most specific alphabet-based class for s by the
// distinguishing characters it contains: hex (all hex digits) is most specific,
// then alnum (only [A-Za-z0-9]), then base64url (adds '_'/'-' and optional '='
// padding), then base64 (adds '+'/'/'). A '=' may only appear as trailing
// padding.
func classifyAlphabet(s []byte) Charclass {
	body := s
	for len(body) > 0 && body[len(body)-1] == '=' {
		body = body[:len(body)-1]
	}
	if len(body) == 0 {
		return ClassOther
	}
	allHex := true
	urlOnly := false // saw '_' or '-'
	stdOnly := false // saw '+' or '/'
	for _, c := range body {
		switch {
		case isHexDigit(c):
		case isAlnumByte(c):
			allHex = false
		case c == '_' || c == '-':
			allHex = false
			urlOnly = true
		case c == '+' || c == '/':
			allHex = false
			stdOnly = true
		default:
			return ClassOther
		}
	}
	hadPad := len(body) != len(s)
	switch {
	case urlOnly && stdOnly:
		return ClassOther
	case stdOnly:
		return ClassBase64
	case urlOnly:
		return ClassBase64URL
	case hadPad:
		return ClassBase64URL
	case allHex:
		return ClassHex
	default:
		return ClassAlnum
	}
}

func isBase64URLSegment(s []byte) bool {
	body := s
	for len(body) > 0 && body[len(body)-1] == '=' {
		body = body[:len(body)-1]
	}
	if len(body) == 0 {
		return false
	}
	for _, c := range body {
		if !isAlnumByte(c) && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func isUUID(s []byte) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !isHexDigit(c) {
			return false
		}
	}
	return true
}

func isJWT(s []byte) bool {
	dots := 0
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			seg := s[start:i]
			if len(seg) == 0 || !isBase64URLSegment(seg) {
				return false
			}
			if i < len(s) {
				dots++
			}
			start = i + 1
		}
	}
	return dots == 2
}

// ShannonEntropy returns the normalized Shannon entropy of s in bits per
// character over the observed byte alphabet (0 for empty or single-symbol
// input).
func ShannonEntropy(s []byte) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range s {
		counts[c]++
	}
	n := float64(len(s))
	var h float64
	for _, cnt := range counts {
		if cnt == 0 {
			continue
		}
		p := float64(cnt) / n
		h -= p * math.Log2(p)
	}
	return h
}

// IsHighEntropyToken reports whether s looks like a high-entropy secret token.
// Length must be in [tokenMinLen, tokenMaxLen]. Structurally typed tokens (UUID,
// JWT) always pass; otherwise a recognized hex/base64/base64url/alnum charclass
// and ShannonEntropy >= tokenMinEntropy are required.
func IsHighEntropyToken(s []byte) bool {
	if len(s) < tokenMinLen || len(s) > tokenMaxLen {
		return false
	}
	switch DetectCharclass(s) {
	case ClassUUID, ClassJWT:
		return true
	case ClassHex, ClassBase64, ClassBase64URL, ClassAlnum:
		return ShannonEntropy(s) >= tokenMinEntropy
	default:
		return false
	}
}

// hash64 is the 64-bit FNV-1a hash of b. It is the token-dedup and value-graph
// hash used by ExtractTokens (extract.go) and the VDG (vdg.go).
func hash64(b []byte) uint64 {
	h := uint64(1469598103934665603)
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}
