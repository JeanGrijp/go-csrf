// Package csrf provides a lightweight double-submit-cookie CSRF protection middleware.
package csrf

import "net/http"

type Config struct {
	// Cookie
	CookieName     string
	CookiePath     string
	CookieDomain   string
	CookieSecure   bool
	CookieSameSite http.SameSite
	CookieMaxAge   int // in seconds

	// Token transport
	HeaderName string // e.g.: "X-CSRF-Token"
	FormField  string // e.g.: "csrf_token"

	// Extra security
	EnforceOriginCheck bool
	AllowedOrigin      string // if empty, uses r.Host

	// Entropy
	TokenBytes int
}

type Protector struct {
	cfg Config
}

func New(cfg Config) *Protector {
	// reasonable defaults
	if cfg.CookieName == "" {
		cfg.CookieName = "csrf_token"
	}
	if cfg.HeaderName == "" {
		cfg.HeaderName = "X-CSRF-Token"
	}
	if cfg.FormField == "" {
		cfg.FormField = "csrf_token"
	}
	if cfg.CookiePath == "" {
		cfg.CookiePath = "/"
	}
	if cfg.TokenBytes <= 0 {
		cfg.TokenBytes = 32
	}
	// modern web security: SameSite=Lax is a good baseline
	if cfg.CookieSameSite == 0 {
		cfg.CookieSameSite = http.SameSiteLaxMode
	}
	return &Protector{cfg: cfg}
}
