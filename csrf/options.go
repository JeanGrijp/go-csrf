// Package csrf provides a lightweight double-submit-cookie CSRF protection middleware.
package csrf

import "net/http"

// Config holds cookie attributes, token transport options and security flags
// used by the CSRF protector. New applies sensible defaults when fields are
// left empty/zero.
//
// Notes
//   - This middleware uses the double-submit cookie pattern, which requires the
//     CSRF cookie to be readable by client-side code; therefore the cookie is set
//     with HttpOnly=false by design.
//   - Defaults applied by New when zero values are provided:
//     CookieName="csrf_token", CookiePath="/", CookieSameSite=http.SameSiteLaxMode,
//     HeaderName="X-CSRF-Token", FormField="csrf_token", TokenBytes=32.
type Config struct {
	// CookieName is the name of the CSRF token cookie.
	// Default: "csrf_token".
	CookieName string

	// CookiePath is the Path attribute for the CSRF cookie.
	// Default: "/".
	CookiePath string

	// CookieDomain is the Domain attribute for the CSRF cookie.
	// Leave empty to omit the attribute.
	CookieDomain string

	// CookieSecure controls the Secure flag of the CSRF cookie.
	// Should be true in production when using HTTPS.
	CookieSecure bool

	// CookieHTTPOnly controls the HttpOnly flag of the CSRF cookie.
	// Default: false (double-submit pattern commonly requires client-side read).
	// Set to true if you always fetch the token via TokenHandler or inject it server-side.
	CookieHTTPOnly bool

	// CookieSameSite sets the SameSite attribute of the CSRF cookie.
	// Default: http.SameSiteLaxMode.
	CookieSameSite http.SameSite

	// CookieMaxAge is the Max-Age attribute in seconds.
	// 0 means a session cookie (no Max-Age attribute). Negative values are not set by this package.
	CookieMaxAge int // in seconds

	// HeaderName is the HTTP header from which the client provides the token
	// on unsafe requests.
	// Default: "X-CSRF-Token".
	HeaderName string

	// FormField is the form field name (application/x-www-form-urlencoded or
	// multipart/form-data) from which the client may provide the token.
	// Default: "csrf_token".
	FormField string

	// EnforceOriginCheck, when true, validates that unsafe requests originate
	// from the same site by checking the Origin header or, if absent, the
	// Referer header.
	EnforceOriginCheck bool

	// AllowedOrigin is the allowed site (host) for same-site checks when
	// EnforceOriginCheck is enabled. If empty, the current request host (r.Host)
	// is used.
	// Example: "app.example.com"
	AllowedOrigin string

	// TokenBytes is the number of random bytes used to generate the token
	// before base64url encoding (no padding).
	// Default: 32.
	TokenBytes int
}

type Protector struct {
	cfg Config
}

// New receives a Config (cfg) with cookie, transport and security settings,
// applies reasonable defaults when fields are empty, and returns a configured
// *Protector ready to be used as middleware. It never returns nil.
//
// Params:
// - cfg: configuration values (cookie options, header/form names, security flags).
//
// Returns:
// - *Protector with defaults applied.
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
