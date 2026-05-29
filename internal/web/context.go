package web

import (
	"context"

	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/web/webctx"
)

// Re-exports of the context helpers. The canonical definitions live in
// internal/web/webctx so handlers can use them without creating an import
// cycle through this package.

func WithUser(ctx context.Context, u *store.User) context.Context  { return webctx.WithUser(ctx, u) }
func UserFromCtx(ctx context.Context) *store.User                  { return webctx.UserFromCtx(ctx) }
func WithSession(ctx context.Context, s *store.Session) context.Context {
	return webctx.WithSession(ctx, s)
}
func SessionFromCtx(ctx context.Context) *store.Session             { return webctx.SessionFromCtx(ctx) }
func WithCSRFToken(ctx context.Context, tok string) context.Context { return webctx.WithCSRFToken(ctx, tok) }
func CSRFTokenFromCtx(ctx context.Context) string                   { return webctx.CSRFTokenFromCtx(ctx) }
func WithRequestID(ctx context.Context, id string) context.Context  { return webctx.WithRequestID(ctx, id) }
func RequestIDFromCtx(ctx context.Context) string                   { return webctx.RequestIDFromCtx(ctx) }
