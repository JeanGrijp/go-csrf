package csrf

import "context"

type ctxKey string

const tokenKey ctxKey = "csrf_token_ctx"

// contextWithToken returns a derived context that stores the given CSRF token.
//
// Params:
// - ctx: base context to attach the token to.
// - tok: CSRF token string to store.
//
// Returns:
// - a new context containing the token.
func contextWithToken(ctx context.Context, tok string) context.Context {
	return context.WithValue(ctx, tokenKey, tok)
}

// tokenFromContext extracts the CSRF token from ctx, if present.
//
// Params:
// - ctx: context possibly containing the token.
//
// Returns:
// - token (string) and a boolean indicating presence.
func tokenFromContext(ctx context.Context) (string, bool) {
	v := ctx.Value(tokenKey)
	if v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}
