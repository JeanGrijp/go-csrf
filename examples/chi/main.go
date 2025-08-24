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
		CookieSecure:       true, // em produção atrás de HTTPS
		EnforceOriginCheck: true,
		AllowedOrigin:      "app.exemplo.com", // se vazio, usa r.Host
	})

	// endpoint opcional para SPA buscar o token
	r.Group(func(r chi.Router) {
		r.Use(p.Protect)
		r.Get("/csrf-token", func(w http.ResponseWriter, r *http.Request) {
			p.TokenHandler().ServeHTTP(w, r)
		})
	})

	// rotas da aplicação
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
			// se chegou aqui, token bateu
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("ok"))
		})
	})

	http.ListenAndServe(":8080", r)
}
