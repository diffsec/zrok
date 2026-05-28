// Package webctx holds the request-context key types and helpers used by both
// the HTTP middleware and the page handlers. It is its own package so handlers
// can depend on it without creating a cycle through internal/web.
package webctx

import (
	"context"

	"github.com/diffsec/quokka/internal/store"
)

type ctxKey int

const (
	keyUser ctxKey = iota
	keySession
	keyCSRFToken
	keyRequestID
)

// WithUser stores the user on the context for downstream handlers.
func WithUser(ctx context.Context, u *store.User) context.Context {
	return context.WithValue(ctx, keyUser, u)
}

// UserFromCtx returns the current authenticated user or nil.
func UserFromCtx(ctx context.Context) *store.User {
	if v, ok := ctx.Value(keyUser).(*store.User); ok {
		return v
	}
	return nil
}

// WithSession stores the active session row on the context.
func WithSession(ctx context.Context, s *store.Session) context.Context {
	return context.WithValue(ctx, keySession, s)
}

// SessionFromCtx returns the current session row or nil.
func SessionFromCtx(ctx context.Context) *store.Session {
	if v, ok := ctx.Value(keySession).(*store.Session); ok {
		return v
	}
	return nil
}

// WithCSRFToken stores the per-session CSRF token literal on the context.
func WithCSRFToken(ctx context.Context, tok string) context.Context {
	return context.WithValue(ctx, keyCSRFToken, tok)
}

// CSRFTokenFromCtx returns the CSRF token from context, empty string if absent.
func CSRFTokenFromCtx(ctx context.Context) string {
	if v, ok := ctx.Value(keyCSRFToken).(string); ok {
		return v
	}
	return ""
}

// WithRequestID stores the request id on the context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, keyRequestID, id)
}

// RequestIDFromCtx returns the request id or empty string.
func RequestIDFromCtx(ctx context.Context) string {
	if v, ok := ctx.Value(keyRequestID).(string); ok {
		return v
	}
	return ""
}
