package csrf

import "context"

type ctxKey string

const tokenKey ctxKey = "csrf_token_ctx"

func contextWithToken(ctx context.Context, tok string) context.Context {
	return context.WithValue(ctx, tokenKey, tok)
}

func tokenFromContext(ctx context.Context) (string, bool) {
	v := ctx.Value(tokenKey)
	if v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}
