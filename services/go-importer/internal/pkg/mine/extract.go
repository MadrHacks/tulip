package mine

// tokenByte reports whether c can appear inside a high-entropy token run:
// alphanumerics plus the structural characters of base64url, UUID, and JWT.
// Standard-base64 '+' '/' and the '=' padding are delimiters, so a value is
// extracted identically whether or not it carries padding, and key=value pairs
// split cleanly into key and value.
func tokenByte(c byte) bool {
	return isAlnumByte(c) || c == '_' || c == '-' || c == '.'
}

// ExtractTokens splits data into maximal token runs and returns the distinct
// high-entropy tokens among them, in first-seen order. It is the producer and
// consumer feed for the value-dataflow graph.
func ExtractTokens(data []byte) [][]byte {
	var out [][]byte
	seen := make(map[uint64]struct{})
	for i := 0; i < len(data); {
		if !tokenByte(data[i]) {
			i++
			continue
		}
		j := i
		for j < len(data) && tokenByte(data[j]) {
			j++
		}
		run := trimDots(data[i:j])
		i = j
		if !IsHighEntropyToken(run) {
			continue
		}
		h := hash64(run)
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, append([]byte(nil), run...))
	}
	return out
}

// trimDots drops leading and trailing '.', which bound sentences, IPs, and
// version strings but never start or end a real token.
func trimDots(b []byte) []byte {
	for len(b) > 0 && b[0] == '.' {
		b = b[1:]
	}
	for len(b) > 0 && b[len(b)-1] == '.' {
		b = b[:len(b)-1]
	}
	return b
}
