package mine

import (
	"math"
	"testing"
)

func TestDetectCharclass(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Charclass
	}{
		{"uuid", "550e8400-e29b-41d4-a716-446655440000", ClassUUID},
		{"uuid-upper", "550E8400-E29B-41D4-A716-446655440000", ClassUUID},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", ClassJWT},
		{"hex-32", "9f86d081884c7d659a2feaa0c55ad015", ClassHex},
		{"hex-short", "abcd", ClassHex},
		{"base64url-dash-underscore", "abc-_DEF123", ClassBase64URL},
		{"base64url-pad", "abc-_DEF12==", ClassBase64URL},
		{"base64url-pad-only", "YWJjZGVm==", ClassBase64URL},
		{"base64-plusslash", "abc+/DEF123", ClassBase64},
		{"base64-pad-plus", "YWJjZG+m==", ClassBase64},
		{"alnum", "Hello123World", ClassAlnum},
		{"alnum-with-g", "GhiJkl", ClassAlnum},
		{"other-space", "hello world", ClassOther},
		{"other-empty", "", ClassOther},
		{"other-symbols", "!@#$%^&*", ClassOther},
		{"mixed-url-and-std", "abc-_+/def", ClassOther},
		{"dash-makes-base64url", "550e8400xe29b-41d4-a716-446655440000", ClassBase64URL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectCharclass([]byte(tc.in)); got != tc.want {
				t.Fatalf("DetectCharclass(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestIsHighEntropyToken(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"hex-32", "9f86d081884c7d659a2feaa0c55ad015", true},
		{"uuid", "550e8400-e29b-41d4-a716-446655440000", true},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", true},
		{"base64url-token", "aZ9-_xQ4kLmN7pR2sT8uVwXy0bCdEfGh", true},
		{"password", "password", false},
		{"helloworld", "helloworld", false},
		{"hex-4-too-short", "abcd", false},
		{"too-long", string(repeatHex(600)), false},
		{"low-entropy-long-alnum", "aaaaaaaaaaaaaaaa", false},
		{"empty", "", false},
		{"symbols-other", "!!!!!!!!!!", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsHighEntropyToken([]byte(tc.in)); got != tc.want {
				t.Fatalf("IsHighEntropyToken(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestShannonEntropy(t *testing.T) {
	if h := ShannonEntropy([]byte("aaaaaaaa")); h > 1e-9 {
		t.Fatalf("ShannonEntropy(aaaaaaaa) = %v, want ~0", h)
	}
	if h := ShannonEntropy(nil); h != 0 {
		t.Fatalf("ShannonEntropy(nil) = %v, want 0", h)
	}
	// "ab" alternating: two equiprobable symbols -> exactly 1 bit/char.
	if h := ShannonEntropy([]byte("abababab")); math.Abs(h-1.0) > 1e-9 {
		t.Fatalf("ShannonEntropy(abababab) = %v, want 1.0", h)
	}
	randomHex := "f3a9c1e07b2d4856af91d3c2e58b6740"
	if h := ShannonEntropy([]byte(randomHex)); h < tokenMinEntropy {
		t.Fatalf("ShannonEntropy(randomHex) = %v, want >= %v", h, tokenMinEntropy)
	}
}

func repeatHex(n int) []byte {
	b := make([]byte, n)
	const hex = "0123456789abcdef"
	for i := range b {
		b[i] = hex[i%16]
	}
	return b
}
