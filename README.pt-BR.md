<div align="center">
  <h1>go-csrf</h1>
  <p>Proteção CSRF leve (double-submit cookie) para Go.</p>
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

Leia em: [English](README.md) • **Português (BR)**

- Funciona com net/http e roteadores populares (chi, gin, etc.)
- API mínima: configure, aplique o middleware e (opcional) exponha um endpoint de token para SPAs
- Defaults seguros (SameSite=Lax, entropia de 32 bytes)

## Links rápidos

- Repositório: https://github.com/JeanGrijp/go-csrf
- Go Reference: https://pkg.go.dev/github.com/JeanGrijp/go-csrf/csrf
- Exemplos: [chi](examples/chi/main.go) • [gin](examples/gin/main.go)

## Instalação

Adicione o pacote ao seu módulo (o pacote está na subpasta `csrf/`):

```sh
go get github.com/JeanGrijp/go-csrf/csrf@latest
```

## Início rápido (chi)

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
        CookieSecure:       true,            // em produção, use HTTPS
        EnforceOriginCheck: true,
        AllowedOrigin:      "app.example.com", // se vazio, usa r.Host
    })

    // Opcional: endpoint para SPA buscar o token atual
    r.Group(func(r chi.Router) {
        r.Use(p.Protect)
        r.Get("/csrf-token", func(w http.ResponseWriter, r *http.Request) {
            p.TokenHandler().ServeHTTP(w, r)
        })
    })

    // Rotas da aplicação protegidas por CSRF
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
            // se chegou aqui, o token foi validado
            w.WriteHeader(http.StatusCreated)
            w.Write([]byte("ok"))
        })
    })

    http.ListenAndServe(":8080", r)
}
```

## Início rápido (net/http)

```go
mux := http.NewServeMux()
// ... registre seus handlers no mux ...

p := csrf.New(csrf.Config{})
protected := p.Protect(mux)

http.ListenAndServe(":8080", protected)
```

## Início rápido (gin)

Este pacote é um middleware padrão de `net/http`. Para usar no Gin, envolva em um `gin.HandlerFunc` e chame `c.Next()` dentro do handler adaptado:

```go
import (
    "net/http"
    "github.com/gin-gonic/gin"
    "github.com/JeanGrijp/go-csrf/csrf"
)

r := gin.New()
p := csrf.New(csrf.Config{})

r.Use(func(c *gin.Context) {
    // Adapta o middleware net/http para o gin
    h := p.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // mantém o contexto do gin em sincronia
        c.Request = r
        c.Next()
    }))
    h.ServeHTTP(c.Writer, c.Request)
})

// Endpoint opcional de token
r.GET("/csrf-token", func(c *gin.Context) {
    p.TokenHandler().ServeHTTP(c.Writer, c.Request)
})
```

## Exemplos

**Arquivos:** [chi](examples/chi/main.go) • [gin](examples/gin/main.go)

Rodar — chi: `go run ./examples/chi` • gin: `go run ./examples/gin`

## Configuração

Toda a configuração é feita via `csrf.Config`:

- CookieName: nome do cookie (padrão `csrf_token`)
- CookiePath: path do cookie (padrão `/`)
- CookieDomain: domínio do cookie
- CookieSecure: habilite em produção com HTTPS
- CookieSameSite: padrão `http.SameSiteLaxMode`
- CookieMaxAge: tempo de vida em segundos
- CookieHTTPOnly: controla o flag HttpOnly do cookie de CSRF (padrão false). Use true se você sempre buscar o token via TokenHandler ou injetá-lo server-side
- HeaderName: header que carrega o token (padrão `X-CSRF-Token`)
- FormField: campo de formulário que carrega o token (padrão `csrf_token`)
- EnforceOriginCheck: quando true, valida Origin/Referer para métodos não seguros
- AllowedOrigin: se vazio, usa o host da requisição atual como site permitido
- TokenBytes: entropia do token em bytes (padrão 32)

Como funciona:
- Métodos seguros (GET/HEAD/OPTIONS): garante a existência do cookie de token; injeta o token no contexto da requisição
- Métodos não seguros (POST/PUT/PATCH/DELETE):
  - Checagem same-site opcional via Origin/Referer
  - Compara o token enviado pelo cliente (header ou form) com o token do cookie (tempo constante)

Obter o token no handler via contexto:

```go
if tok, ok := csrf.TokenFromContext(r.Context()); ok {
    // use o tok
}
```

Expor um endpoint de token (útil para SPAs):

```go
r.Get("/csrf-token", func(w http.ResponseWriter, r *http.Request) {
    p.TokenHandler().ServeHTTP(w, r)
})
```

## Notas de segurança

- Sempre habilite `CookieSecure` em produção (HTTPS).
- HttpOnly: por padrão o cookie de CSRF usa HttpOnly=false por compatibilidade. Se você não precisa ler o cookie no JS, prefira `CookieHTTPOnly=true` e busque o token pelo endpoint `/csrf-token` (TokenHandler) ou injete server-side.
- Observação: CSRF não protege contra XSS. Se um invasor executa JS, ele também pode chamar o endpoint de token; HttpOnly sozinho não mitiga XSS.
- Considere habilitar `EnforceOriginCheck` para mitigar CSRF via política de mesmo site.

## Desenvolvimento

Rodar o exemplo com chi:

```sh
go run ./examples/chi
```

Rodar o exemplo com gin:

```sh
go run ./examples/gin
```

## Licença

MIT
