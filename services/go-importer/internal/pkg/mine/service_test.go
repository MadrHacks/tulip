package mine

import "testing"

func TestServiceName(t *testing.T) {
	cases := map[string]string{
		"CCalendar-1":     "CCalendar",
		"CCForms-2":       "CCForms",
		"ExCCel":          "ExCCel",
		"CookingNonna-10": "CookingNonna",
		"foo-bar":         "foo-bar",
		"a-1":             "a",
		"x-":              "x-",
		"-1":              "-1",
		"":                "",
	}
	for in, want := range cases {
		if got := ServiceName(in); got != want {
			t.Errorf("ServiceName(%q) = %q, want %q", in, got, want)
		}
	}
}
