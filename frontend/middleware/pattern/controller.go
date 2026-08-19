package pattern

import (
	"context"
	"net/http"
)

type ctxKey struct{}

func withPattern(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, ctxKey{}, value)
}

func (h *Handler) PatternMw(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := withPattern(r.Context(), h.pattern)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetPattern(ctx context.Context) string {
	if value, ok := ctx.Value(ctxKey{}).(string); ok {
		return value
	}
	return ""
}
