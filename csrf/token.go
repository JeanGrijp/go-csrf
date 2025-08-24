package csrf

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
)

// newToken generates a random URL-safe token.
func newToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// base64 URL-encoding without padding
	s := base64.RawURLEncoding.EncodeToString(b)
	return s, nil
}

func extractClientToken(r *http.Request, headerName, formField string) string {
	// Header vence
	if h := r.Header.Get(headerName); h != "" {
		return h
	}
	// Depois tenta form (x-www-form-urlencoded / multipart)
	_ = r.ParseForm()
	if v := r.Form.Get(formField); v != "" {
		return v
	}
	return ""
}

// sameSite checks if originOrRef is same-site with the allowed host.
func sameSite(originOrRef, allowedHost string) bool {
	u, err := url.Parse(originOrRef)
	if err != nil {
		return false
	}
	// Compara apenas host (pode incluir porta). Opcional: normalizar porta padrão.
	return strings.EqualFold(u.Host, allowedHost)
}
