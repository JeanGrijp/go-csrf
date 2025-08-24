// Package csrf provides lightweight CSRF protection for Go net/http servers
// using the double-submit cookie pattern.
//
// How it works
//   - Safe methods (GET, HEAD, OPTIONS): ensure a CSRF token cookie exists and
//     inject the token into the request context so handlers can read it via
//     TokenFromContext.
//   - Unsafe methods (POST, PUT, PATCH, DELETE): optionally enforce same-site
//     policy using Origin/Referer (when EnforceOriginCheck is enabled) and then
//     require the client-provided token (from header or form field) to match the
//     token stored in the cookie. Comparison is done in constant time.
//
// # Configuration
//
// All behavior is driven by Config. Key fields include:
//   - CookieName, CookiePath, CookieDomain, CookieSecure, CookieSameSite, CookieMaxAge
//   - HeaderName (default: "X-CSRF-Token")
//   - FormField (default: "csrf_token")
//   - EnforceOriginCheck and AllowedOrigin (empty means use the request host)
//   - TokenBytes (default: 32)
//
// Typical usage
//
//	p := csrf.New(csrf.Config{ EnforceOriginCheck: true })
//	// Protect an http.Handler (router, mux, etc.)
//	protected := p.Protect(appMux)
//	http.ListenAndServe(":8080", protected)
//
// In handlers, you can read the token from context for rendering or APIs:
//
//	if tok, ok := csrf.TokenFromContext(r.Context()); ok {
//	    // use tok in templates or return it from an endpoint
//	}
//
// For SPAs, expose a small endpoint that returns the current token:
//
//	r.Get("/csrf-token", func(w http.ResponseWriter, r *http.Request) {
//	    p.TokenHandler().ServeHTTP(w, r)
//	})
package csrf
