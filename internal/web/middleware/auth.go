package middleware

import (
	"net/http"
	"strings"

	"github.com/diffsec/quokka/internal/web/webctx"
)

// authSkipPrefixes are paths that must remain accessible to anonymous users.
var authSkipPrefixes = []string{
	"/login",
	"/oauth/callback",
	"/healthz",
	"/static/",
	"/webhooks/",
}

// RequireAuth redirects anonymous requests to /login?next=<original>.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if skip(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if webctx.UserFromCtx(r.Context()) == nil {
			next := r.URL.RequestURI()
			http.Redirect(w, r, "/login?next="+urlPathEncode(next), http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAdmin returns 403 if the current user's role != admin.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := webctx.UserFromCtx(r.Context())
		if u == nil || u.Role != "admin" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func skip(path string) bool {
	for _, p := range authSkipPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// urlPathEncode lightly escapes the `next` redirect target. We only need to
// keep ?, & and # from being interpreted by the surrounding URL.
func urlPathEncode(s string) string {
	r := strings.NewReplacer("?", "%3F", "&", "%26", "#", "%23", " ", "%20")
	return r.Replace(s)
}
