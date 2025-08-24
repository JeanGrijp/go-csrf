package main

import (
	"fmt"
	"net/http"

	"github.com/JeanGrijp/go-csrf/csrf"
	"github.com/gin-gonic/gin"
)

// CsrfMiddleware adapts the net/http CSRF middleware to Gin.
func CsrfMiddleware(p *csrf.Protector) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := p.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// keep gin context in sync with possibly modified *http.Request
			c.Request = r
			c.Next()
		}))
		h.ServeHTTP(c.Writer, c.Request)
	}
}

func main() {
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	p := csrf.New(csrf.Config{
		CookieSecure:       true, // in production behind HTTPS
		EnforceOriginCheck: true,
		AllowedOrigin:      "app.example.com", // if empty, uses r.Host
	})
	csrfMW := CsrfMiddleware(p)

	// Optional endpoint for SPA to fetch the token (protected so cookie+context are set)
	token := r.Group("/")
	token.Use(csrfMW)
	token.GET("/csrf-token", func(c *gin.Context) {
		p.TokenHandler().ServeHTTP(c.Writer, c.Request)
	})

	// Application routes protected by CSRF
	app := r.Group("/")
	app.Use(csrfMW)
	app.GET("/", func(c *gin.Context) {
		if tok, ok := csrf.TokenFromContext(c.Request.Context()); ok {
			c.String(http.StatusOK, fmt.Sprintf("Hello! CSRF token: %s", tok))
			return
		}
		c.String(http.StatusOK, "Hello!")
	})
	app.POST("/transfer", func(c *gin.Context) {
		// if we got here, the token was valid
		c.String(http.StatusCreated, "ok")
	})

	http.ListenAndServe(":8080", r)
}
