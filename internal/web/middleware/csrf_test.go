package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCSRF_AllowsGET(t *testing.T) {
	h := CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET expected 200, got %d", w.Code)
	}
}

func TestCSRF_RejectsPOSTWithoutCookie(t *testing.T) {
	h := CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("downstream handler should not run")
	}))
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestCSRF_RejectsMismatch(t *testing.T) {
	h := CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not run")
	}))
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "cookieval"})
	r.Header.Set("X-CSRF-Token", "headerval")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestCSRF_AllowsMatchedHeader(t *testing.T) {
	ran := false
	h := CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "tok-123"})
	r.Header.Set("X-CSRF-Token", "tok-123")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !ran {
		t.Fatal("downstream not called")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestCSRF_AllowsMatchedFormField(t *testing.T) {
	ran := false
	h := CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
	}))
	body := strings.NewReader("csrf_token=tok-abc&foo=bar")
	r := httptest.NewRequest(http.MethodPost, "/x", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "tok-abc"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !ran || w.Code >= 400 {
		t.Fatalf("form field path failed: ran=%v code=%d", ran, w.Code)
	}
}

func TestCSRF_SkipOAuthCallback(t *testing.T) {
	ran := false
	h := CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
	}))
	r := httptest.NewRequest(http.MethodPost, "/oauth/callback?code=x", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !ran {
		t.Fatalf("oauth callback should be exempt, got code=%d", w.Code)
	}
}
