<div align="center">
	<h1>go-csrf</h1>
	<p>Lightweight double-submit cookie CSRF protection for Go.</p>
	<p>
		<a href="https://github.com/JeanGrijp/go-csrf/actions/workflows/ci.yml">
			<img src="https://github.com/JeanGrijp/go-csrf/actions/workflows/ci.yml/badge.svg" alt="CI">
		</a>
		<a href="https://codecov.io/gh/JeanGrijp/go-csrf">
			<img src="https://codecov.io/gh/JeanGrijp/go-csrf/graph/badge.svg?token=REPLACE_TOKEN" alt="codecov">
		</a>
		<a href="https://pkg.go.dev/github.com/JeanGrijp/go-csrf/csrf">
			<img src="https://pkg.go.dev/badge/github.com/JeanGrijp/go-csrf/csrf.svg" alt="Go Reference">
		</a>
		<a href="https://goreportcard.com/report/github.com/JeanGrijp/go-csrf">
			<img src="https://goreportcard.com/badge/github.com/JeanGrijp/go-csrf" alt="Go Report Card">
		</a>
		<a href="LICENSE">
			<img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT">
		</a>
	</p>
</div>

Read this in: **English** • [Português (BR)](README.pt-BR.md)

- Works with net/http and popular routers (chi, gin, etc.)
- Minimal API: configure, attach middleware, optionally expose a token endpoint for SPAs
- Safe defaults (SameSite=Lax, 32 bytes entropy)

**Examples:** [chi](examples/chi/main.go) • [gin](examples/gin/main.go)

Run — chi: `go run ./examples/chi` • gin: `go run ./examples/gin`

## Install

Add the package to your module (the package lives under the `csrf/` subfolder):

```sh
go get github.com/JeanGrijp/go-csrf/csrf@latest
```

## Quick start (chi)

```go
package main

import (
	"fmt"
	"net/http"

	"github.com/JeanGrijp/go-csrf/csrf"
	"github.com/go-chi/chi/v5"
)

func main() {
	r := chi.NewRouter()

	p := csrf.New(csrf.Config{
		CookieSecure:       true,            // in production behind HTTPS
		EnforceOriginCheck: true,
		AllowedOrigin:      "app.example.com", // if empty, uses r.Host
	})

	// Optional: SPA endpoint to fetch the current token
	r.Group(func(r chi.Router) {
		r.Use(p.Protect)
		r.Get("/csrf-token", func(w http.ResponseWriter, r *http.Request) {
			p.TokenHandler().ServeHTTP(w, r)
		})
	})

	// App routes protected by CSRF
	r.Group(func(r chi.Router) {
		r.Use(p.Protect)

		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			if tok, ok := csrf.TokenFromContext(r.Context()); ok {
				fmt.Fprintf(w, "Hello! CSRF token: %s", tok)
				return
			}
			fmt.Fprint(w, "Hello!")
		})

		r.Post("/transfer", func(w http.ResponseWriter, r *http.Request) {
			// if we got here, the token was valid
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("ok"))
		})
	})

	http.ListenAndServe(":8080", r)
}
```

## Quick start (net/http)

```go
mux := http.NewServeMux()
// ... register handlers on mux ...

p := csrf.New(csrf.Config{})
protected := p.Protect(mux)

http.ListenAndServe(":8080", protected)
```

## Quick start (gin)

This package is a standard `net/http` middleware. To use it in Gin, wrap it into a `gin.HandlerFunc` and forward to `c.Next()` inside the wrapped handler:

```go
import (
	"net/http"
	"github.com/gin-gonic/gin"
	"github.com/JeanGrijp/go-csrf/csrf"
)

r := gin.New()
p := csrf.New(csrf.Config{})

r.Use(func(c *gin.Context) {
	// Adapt net/http middleware to gin
	h := p.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// keep gin context in sync
		c.Request = r
		c.Next()
	}))
	h.ServeHTTP(c.Writer, c.Request)
})

// Optional token endpoint
r.GET("/csrf-token", func(c *gin.Context) {
	p.TokenHandler().ServeHTTP(c.Writer, c.Request)
})
```

## Configuration

All configuration happens via `csrf.Config`:

- CookieName: cookie name (default `csrf_token`)
- CookiePath: cookie path (default `/`)
- CookieDomain: cookie domain
- CookieSecure: set to true in production behind HTTPS
- CookieSameSite: defaults to `http.SameSiteLaxMode`
- CookieMaxAge: lifetime in seconds
- HeaderName: header that carries the token (default `X-CSRF-Token`)
- FormField: form field that carries the token (default `csrf_token`)
- EnforceOriginCheck: when true, validates Origin/Referer for unsafe methods
- AllowedOrigin: when empty, the current request host is used as the allowed site
- TokenBytes: token entropy in bytes (default 32)

How it works:
- Safe methods (GET/HEAD/OPTIONS): ensures the token cookie exists; injects the token into request context
- Unsafe methods (POST/PUT/PATCH/DELETE):
  - Optional same-site check via Origin/Referer
  - Compares client-provided token (header or form field) to the cookie token (constant-time)

Grab the token in handlers via context:

```go
if tok, ok := csrf.TokenFromContext(r.Context()); ok {
	// use tok
}
```

Expose a token endpoint (useful for SPAs):

```go
r.Get("/csrf-token", func(w http.ResponseWriter, r *http.Request) {
	p.TokenHandler().ServeHTTP(w, r)
})
```

## Security notes

- Always enable `CookieSecure` in production (HTTPS).
- Double-submit requires the token to be readable by JS (`HttpOnly` is intentionally false for the CSRF cookie).
- Consider enabling `EnforceOriginCheck` to mitigate CSRF via strict same-site policy.

## Development

Run the chi example:

```sh
go run ./examples/chi
```

Run the gin example:

```sh
go run ./examples/gin
```

## License

MIT