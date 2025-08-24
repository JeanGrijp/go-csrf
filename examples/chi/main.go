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
		CookieSecure:       true, // in production behind HTTPS
		EnforceOriginCheck: true,
		AllowedOrigin:      "app.example.com", // if empty, uses r.Host
	})

	// optional endpoint for SPA to fetch the token
	r.Group(func(r chi.Router) {
		r.Use(p.Protect)
		r.Get("/csrf-token", func(w http.ResponseWriter, r *http.Request) {
			p.TokenHandler().ServeHTTP(w, r)
		})
	})

	// application routes
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
