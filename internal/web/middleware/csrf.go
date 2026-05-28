package middleware

import (
	"net/http"
	"strings"

	"github.com/diffsec/quokka/internal/web/webctx"
)

// csrfSkipPrefixes are POST endpoints exempt from CSRF (state-cookie- or
// signature-protected paths).
var csrfSkipPrefixes = []string{
	"/oauth/callback",
}

// CSRF enforces a double-submit cookie check on non-GET/HEAD requests.
// The token is also propagated to the request context so layouts can render
// it into a <meta> tag.
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie(CSRFCookieName)
		if c != nil {
			r = r.WithContext(webctx.WithCSRFToken(r.Context(), c.Value))
		}
		if isSafeMethod(r.Method) || csrfSkip(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if c == nil || c.Value == "" {
			http.Error(w, "missing csrf cookie", http.StatusForbidden)
			return
		}
		hdr := r.Header.Get("X-CSRF-Token")
		if hdr == "" {
			// Fall back to form value (HTMX users typically send the header,
			// but pure form posts may not). Look for csrf_token in form body.
			if err := r.ParseForm(); err == nil {
				hdr = r.PostForm.Get("csrf_token")
			}
		}
		if hdr == "" || hdr != c.Value {
			http.Error(w, "csrf token mismatch", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

func csrfSkip(path string) bool {
	for _, p := range csrfSkipPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}
