package mine

import (
	"testing"
)

func TestPathTemplate(t *testing.T) {
	cases := map[string]string{
		"/api/note/42":        "/api/note/{}",
		"/users/deadbeefcafe": "/users/{}",
		"/static/app.js":      "/static/app.js",
		"/":                   "/",
	}
	for in, want := range cases {
		if got := pathTemplate(in); got != want {
			t.Errorf("pathTemplate(%q) = %q, want %q", in, got, want)
		}
	}
}
