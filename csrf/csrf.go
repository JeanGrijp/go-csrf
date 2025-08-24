package csrf

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
)

// Methods that require CSRF protection
var unsafeMethods = map[string]bool{
	http.MethodPost:   true,
	http.MethodPut:    true,
	http.MethodPatch:  true,
	http.MethodDelete: true,
}

// Protect wraps the given next http.Handler and enforces CSRF protection.
//
// Behavior:
//   - For "safe" methods (GET/HEAD/OPTIONS): ensures the token cookie exists and
//     injects the token into the request context, then calls next.
//   - For "unsafe" methods (POST/PUT/PATCH/DELETE): optionally validates Origin/Referer
//     (when EnforceOriginCheck is true), extracts the client token from header or form,
//     compares it in constant time against the cookie token, and only then calls next.
//
// Params:
// - next: downstream handler to be executed after CSRF checks pass.
//
// Returns:
// - An http.Handler that performs the CSRF logic before delegating to next.
func (p *Protector) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := p.cfg

		// 1) always ensure the cookie exists
		cookieToken, err := p.ensureCookieToken(w, r)
		if err != nil {
			http.Error(w, "failed to set CSRF cookie", http.StatusInternalServerError)
			return
		}

		// inject the token into the request context for downstream handlers
		r = r.WithContext(contextWithToken(r.Context(), cookieToken))

		// 2) for safe methods, just continue
		if !unsafeMethods[r.Method] {
			next.ServeHTTP(w, r)
			return
		}

		// 3) Origin/Referer validation (if enabled)
		if cfg.EnforceOriginCheck {
			if err := validateOriginOrReferer(r, cfg.AllowedOrigin); err != nil {
				http.Error(w, "invalid origin", http.StatusForbidden)
				return
			}
		}

		// 4) extract client-provided token (header or form)
		clientToken := extractClientToken(r, cfg.HeaderName, cfg.FormField)
		if clientToken == "" {
			http.Error(w, "missing CSRF token", http.StatusForbidden)
			return
		}

		// 5) time-constant compare
		if subtle.ConstantTimeCompare([]byte(clientToken), []byte(cookieToken)) != 1 {
			http.Error(w, "bad CSRF token", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ensureCookieToken checks for the CSRF token cookie on the incoming request.
// If present and looks valid, it returns the cookie value. Otherwise, it generates
// a new random token, sets it as a cookie on the response, and returns the value.
//
// Params:
// - w: response writer used to set the cookie when needed.
// - r: incoming request to inspect cookies from.
//
// Returns:
// - token string on success; empty string and error if token generation fails.
func (p *Protector) ensureCookieToken(w http.ResponseWriter, r *http.Request) (string, error) {
	cfg := p.cfg

	if c, err := r.Cookie(cfg.CookieName); err == nil && len(c.Value) >= 16 {
		return c.Value, nil
	}

	tok, err := newToken(cfg.TokenBytes)
	if err != nil {
		return "", err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CookieName,
		Value:    tok,
		Path:     cfg.CookiePath,
		Domain:   cfg.CookieDomain,
		MaxAge:   cfg.CookieMaxAge,
		SameSite: cfg.CookieSameSite,
		Secure:   cfg.CookieSecure,
		HttpOnly: cfg.CookieHTTPOnly,
	})

	return tok, nil
}

// TokenFromContext returns the CSRF token stored in ctx, if present.
//
// Params:
// - ctx: context potentially containing a token set by the middleware.
//
// Returns:
// - token (string) and a boolean indicating whether a token was found.
func TokenFromContext(ctx context.Context) (string, bool) {
	return tokenFromContext(ctx)
}

// TokenHandler returns an HTTP handler that writes the current CSRF token.
// This is useful for SPAs to fetch the token and attach it to subsequent requests.
//
// Returns:
// - http.Handler that responds with the token in the response body (text/plain).
func (p *Protector) TokenHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tok, ok := TokenFromContext(r.Context()); ok {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write([]byte(tok))
			return
		}
		http.Error(w, "no token", http.StatusInternalServerError)
	})
}

// validateOriginOrReferer checks whether the request is same-site according to
// the allowed host policy. When allowed is empty, it falls back to r.Host.
// It prefers the Origin header; if empty, it falls back to Referer.
//
// Params:
//   - r: the incoming request containing Origin/Referer headers.
//   - allowed: the allowed host (domain[:port]) to be considered same-site;
//     if empty, r.Host is used.
//
// Returns:
// - nil when origin/referrer is acceptable; otherwise an error describing the issue.
func validateOriginOrReferer(r *http.Request, allowed string) error {
	// if allowed is empty, use the current request host as baseline
	host := allowed
	if host == "" {
		host = r.Host
	}

	// Prefer Origin; if empty, use Referer.
	origin := r.Header.Get("Origin")
	ref := r.Header.Get("Referer")

	if origin == "" && ref == "" {
		return errors.New("no origin/referer")
	}
	if origin != "" && !sameSite(origin, host) {
		return errors.New("bad origin")
	}
	if origin == "" && ref != "" && !sameSite(ref, host) {
		return errors.New("bad referer")
	}
	return nil
}
