package gosso

import "testing"

func TestSanitizeRedirect(t *testing.T) {
	cases := []struct {
		name  string
		raw   string
		valid string
	}{
		{name: "empty", raw: "", valid: "/"},
		{name: "root", raw: "/", valid: "/"},
		{name: "path", raw: "/jobs/1", valid: "/jobs/1"},
		{name: "query preserved", raw: "/jobs/1?page=2", valid: "/jobs/1?page=2"},
		{name: "percent in path", raw: "/jobs/100%25", valid: "/jobs/100%25"},
		{name: "absolute", raw: "https://evil.example.com", valid: "/"},
		{name: "scheme other", raw: "javascript:alert(1)", valid: "/"},
		{name: "protocol relative", raw: "//evil.example.com", valid: "/"},
		{name: "encoded protocol relative", raw: "/%2F%2Fevil.example.com", valid: "/"},
		{name: "mixed encoded protocol relative", raw: "/%2f%2fevil.example.com", valid: "/"},
		{name: "doubly encoded", raw: "/%252F%252Fevil.example.com", valid: "/"},
		{name: "encoded backslash", raw: "/%5Cevil", valid: "/"},
		{name: "backslash", raw: "/\\evil", valid: "/"},
		{name: "backslash in path", raw: "/jobs/\\..\\admin", valid: "/"},
		{name: "nul byte", raw: "/\x00evil", valid: "/"},
	}

	for _, tc := range cases {
		if got := SanitizeRedirect(tc.raw); got != tc.valid {
			t.Errorf("%s: SanitizeRedirect(%q) = %q, want %q", tc.name, tc.raw, got, tc.valid)
		}
	}
}
