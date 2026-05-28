// Package middleware contains the HTTP middleware shared by all web routes.
package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/diffsec/quokka/internal/web/webctx"
)

// RequestID assigns each request a 16-hex-char id, surfacing it both on the
// context and on the response header. Useful for log correlation.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set("X-Request-ID", id)
		r = r.WithContext(webctx.WithRequestID(r.Context(), id))
		next.ServeHTTP(w, r)
	})
}

func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
