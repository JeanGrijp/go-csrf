package csrf

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
)

// newToken generates a random URL-safe token.
//
// Params:
// - n: number of random bytes before base64-url encoding (entropy size).
//
// Returns:
// - token (string) on success; empty string and error if randomness fails.
func newToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// base64 URL-encoding without padding
	s := base64.RawURLEncoding.EncodeToString(b)
	return s, nil
}

// extractClientToken tries to read the CSRF token provided by the client.
//
// It first checks the header name provided, and if empty, it falls back to
// the form field (works for x-www-form-urlencoded and multipart).
//
// Params:
// - r: incoming request possibly containing header or form token.
// - headerName: the HTTP header to read the token from (e.g., X-CSRF-Token).
// - formField: the form field name to read the token from.
//
// Returns:
// - the token string if found; otherwise empty string.
func extractClientToken(r *http.Request, headerName, formField string) string {
	// Check header first
	if h := r.Header.Get(headerName); h != "" {
		return h
	}
	// Then check form (x-www-form-urlencoded / multipart)
	_ = r.ParseForm()
	if v := r.Form.Get(formField); v != "" {
		return v
	}
	return ""
}

// sameSite checks if originOrRef is same-site with the allowed host.
// It compares only the host (which may include the port).
//
// Params:
// - originOrRef: Origin or Referer URL string.
// - allowedHost: the host to consider same-site against.
//
// Returns:
// - true if the parsed URL host matches allowedHost (case-insensitive); false otherwise.
func sameSite(originOrRef, allowedHost string) bool {
	u, err := url.Parse(originOrRef)
	if err != nil {
		return false
	}
	// Compara apenas host (pode incluir porta). Opcional: normalizar porta padrão.
	return strings.EqualFold(u.Host, allowedHost)
}
