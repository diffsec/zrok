package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/diffsec/quokka/internal/web/webctx"
)

// Recover converts any panic in a downstream handler into a 500. The slog
// logger is used to record the stack; nil falls back to slog.Default.
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					if log == nil {
						log = slog.Default()
					}
					log.Error("panic",
						slog.Any("err", rec),
						slog.String("stack", string(debug.Stack())),
						slog.String("path", r.URL.Path),
						slog.String("req_id", webctx.RequestIDFromCtx(r.Context())),
					)
					http.Error(w, "internal server error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
