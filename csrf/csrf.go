package csrf

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
)

// Métodos que exigem proteção
var unsafeMethods = map[string]bool{
	http.MethodPost:   true,
	http.MethodPut:    true,
	http.MethodPatch:  true,
	http.MethodDelete: true,
}

// Middleware principal.
// - Em métodos "safe": garante que o cookie do token exista (gera se precisar).
// - Em métodos "unsafe": valida header/body vs cookie e (opcionalmente) Origin/Referer.
func (p *Protector) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := p.cfg

		// 1) sempre tenta garantir que o cookie exista
		cookieToken, err := p.ensureCookieToken(w, r)
		if err != nil {
			http.Error(w, "failed to set CSRF cookie", http.StatusInternalServerError)
			return
		}

		// injeta o token no contexto para handlers que queiram expor/usar
		r = r.WithContext(contextWithToken(r.Context(), cookieToken))

		// 2) se for safe, segue o jogo
		if !unsafeMethods[r.Method] {
			next.ServeHTTP(w, r)
			return
		}

		// 3) validação de Origin/Referer (se habilitado)
		if cfg.EnforceOriginCheck {
			if err := validateOriginOrReferer(r, cfg.AllowedOrigin); err != nil {
				http.Error(w, "invalid origin", http.StatusForbidden)
				return
			}
		}

		// 4) extrai token enviado pelo cliente (header ou form)
		clientToken := extractClientToken(r, cfg.HeaderName, cfg.FormField)
		if clientToken == "" {
			http.Error(w, "missing CSRF token", http.StatusForbidden)
			return
		}

		// 5) compara de forma segura (time-constant)
		if subtle.ConstantTimeCompare([]byte(clientToken), []byte(cookieToken)) != 1 {
			http.Error(w, "bad CSRF token", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Garante que o cookie do token exista; se não existir, gera e seta.
func (p *Protector) ensureCookieToken(w http.ResponseWriter, r *http.Request) (string, error) {
	cfg := p.cfg

	if c, err := r.Cookie(cfg.CookieName); err == nil && len(c.Value) >= 16 {
		return c.Value, nil
	}

	tok, err := newToken(cfg.TokenBytes)
	if err != nil {
		return "", err
	}

	// HttpOnly = false (double-submit precisa ser legível por JS)
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CookieName,
		Value:    tok,
		Path:     cfg.CookiePath,
		Domain:   cfg.CookieDomain,
		MaxAge:   cfg.CookieMaxAge,
		SameSite: cfg.CookieSameSite,
		Secure:   cfg.CookieSecure,
		HttpOnly: false,
	})

	return tok, nil
}

// Helpers para expor token no contexto ao app.
func TokenFromContext(ctx context.Context) (string, bool) {
	return tokenFromContext(ctx)
}

// Cria um handler utilitário opcional que retorna o token atual (para SPAs).
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

func validateOriginOrReferer(r *http.Request, allowed string) error {
	// se não houver allowed definido, usa o Host atual como base
	host := allowed
	if host == "" {
		host = r.Host
	}

	// Preferimos Origin; se vazio, usamos Referer.
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
