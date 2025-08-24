package csrf

import "net/http"

type Config struct {
	// Cookie
	CookieName     string
	CookiePath     string
	CookieDomain   string
	CookieSecure   bool
	CookieSameSite http.SameSite
	CookieMaxAge   int // em segundos

	// Token transport
	HeaderName string // ex: "X-CSRF-Token"
	FormField  string // ex: "csrf_token"

	// Segurança extra
	EnforceOriginCheck bool
	AllowedOrigin      string // se vazio, usa r.Host

	// Entropia
	TokenBytes int
}

type Protector struct {
	cfg Config
}

func New(cfg Config) *Protector {
	// defaults razoáveis
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
	// segurança web moderna: SameSite=Lax geralmente é o mínimo
	if cfg.CookieSameSite == 0 {
		cfg.CookieSameSite = http.SameSiteLaxMode
	}
	return &Protector{cfg: cfg}
}
