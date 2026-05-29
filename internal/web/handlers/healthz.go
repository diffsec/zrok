package handlers

import (
	"net/http"
)

// Healthz returns 200 with a plain text "ok" body. Used by container probes.
func Healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}
