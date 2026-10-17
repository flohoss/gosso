package gosso

import (
	"net/url"
	"strings"
)

// maxRedirectDecodePasses bounds how often SanitizeRedirect percent-decodes a target before
// judging it, covering browsers that decode once per redirect hop.
const maxRedirectDecodePasses = 3

// SanitizeRedirect keeps only same-origin absolute paths and falls back to "/" for anything else.
// Percent-encoded and backslash variants that browsers normalize back into protocol-relative
// URLs, such as "/%2F%2Fevil.example.com", are rejected as well.
func SanitizeRedirect(raw string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") {
		return "/"
	}

	decoded := raw
	for range maxRedirectDecodePasses {
		unescaped, err := url.PathUnescape(decoded)
		if err != nil || unescaped == decoded {
			break
		}

		decoded = unescaped
	}

	if !strings.HasPrefix(decoded, "/") || strings.HasPrefix(decoded, "//") ||
		strings.Contains(decoded, "\\") || strings.ContainsRune(decoded, 0) {
		return "/"
	}

	return raw
}
