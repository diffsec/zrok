package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/web/webctx"
)

// Session cookie + CSRF cookie names used across middleware and handlers.
const (
	SessionCookieName = "q_session"
	CSRFCookieName    = "q_csrf"

	// SessionTTL is the sliding-renewal window: every authenticated request
	// extends expires_at by this much.
	SessionTTL = 30 * 24 * time.Hour
)

// Session loads the user from the q_session cookie and attaches it to the
// request context. Missing or expired sessions yield an anonymous context.
// On a touched session the q_session cookie is rewritten with a fresh Max-Age
// so the browser also slides forward.
func Session(stores *store.Stores, secureCookies bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(SessionCookieName)
			if err != nil || c.Value == "" {
				next.ServeHTTP(w, r)
				return
			}
			sess, err := stores.Sessions.Get(r.Context(), c.Value)
			if err != nil {
				if !errors.Is(err, store.ErrNotFound) {
					// Lookup failure shouldn't crash the request — proceed
					// anonymous, the logging middleware will record context.
				}
				clearCookie(w, SessionCookieName, "/", secureCookies)
				next.ServeHTTP(w, r)
				return
			}
			now := time.Now().UTC()
			if !sess.ExpiresAt.IsZero() && now.After(sess.ExpiresAt) {
				_ = stores.Sessions.Delete(r.Context(), sess.ID)
				clearCookie(w, SessionCookieName, "/", secureCookies)
				next.ServeHTTP(w, r)
				return
			}
			u, err := stores.Users.Get(r.Context(), sess.UserID)
			if err != nil {
				clearCookie(w, SessionCookieName, "/", secureCookies)
				next.ServeHTTP(w, r)
				return
			}
			// Slide expires_at forward.
			newExp := now.Add(SessionTTL)
			if err := stores.Sessions.Touch(r.Context(), sess.ID, now, newExp); err == nil {
				sess.LastSeenAt = now
				sess.ExpiresAt = newExp
				WriteSessionCookie(w, sess.ID, secureCookies)
			}

			ctx := webctx.WithUser(r.Context(), u)
			ctx = webctx.WithSession(ctx, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// WriteSessionCookie sets the q_session cookie with the configured TTL.
// Exported so the OAuth callback can call it right after Create.
func WriteSessionCookie(w http.ResponseWriter, id string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(SessionTTL / time.Second),
	})
}

// WriteCSRFCookie mints a non-HttpOnly cookie that the JS in the page can read
// and surface via the X-CSRF-Token header on htmx requests.
func WriteCSRFCookie(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(SessionTTL / time.Second),
	})
}

// NewCSRFToken returns a fresh 32-byte hex token.
func NewCSRFToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func clearCookie(w http.ResponseWriter, name, path string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearCookies clears both q_session and q_csrf. Exported for /logout.
func ClearCookies(w http.ResponseWriter, secure bool) {
	clearCookie(w, SessionCookieName, "/", secure)
	clearCookie(w, CSRFCookieName, "/", secure)
}
