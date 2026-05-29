package web_test

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diffsec/quokka/db/migrations"
	"github.com/diffsec/quokka/internal/github"
	"github.com/diffsec/quokka/internal/store"
	_ "github.com/diffsec/quokka/internal/store/sql/sqlite"
	"github.com/diffsec/quokka/internal/web"
	"github.com/diffsec/quokka/internal/worker/queue"
)

func randB64Key(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func sign(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestWebhookEndpointEnqueuesRunPR(t *testing.T) {
	t.Setenv("QUOKKA_MASTER_KEY", randB64Key(t))
	t.Setenv("QUOKKA_MASTER_KEY_OLD", "")
	dir := t.TempDir()
	dsn := "sqlite://" + filepath.Join(dir, "test.db")
	stores, err := store.Open(context.Background(), store.Config{DSN: dsn, DataRoot: dir})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = stores.Close() }()
	if err := migrations.Up(migrations.DialectSQLite, stores.DB); err != nil {
		t.Fatalf("migrate up: %v", err)
	}

	q := queue.NewSQLQueue(stores.Jobs)
	enq := func(ctx context.Context, jobType string, payload any, key string) (bool, error) {
		b, _ := json.Marshal(payload)
		_, ins, err := q.Enqueue(ctx, &queue.Job{
			Type:           jobType,
			PayloadJSON:    string(b),
			IdempotencyKey: key,
		})
		return ins, err
	}

	srv := web.NewServer(web.Config{
		Addr:           ":0",
		BaseURL:        "http://localhost:8080",
		Stores:         stores,
		WebhookSecret:  "shhh",
		WebhookEnqueue: enq,
	})

	body, _ := json.Marshal(map[string]any{
		"action": "opened",
		"number": 7,
		"pull_request": map[string]any{
			"base": map[string]any{"sha": "b"},
			"head": map[string]any{"sha": "h"},
		},
		"repository":   map[string]any{"id": 1234, "full_name": "acme/widget"},
		"installation": map[string]any{"id": 99},
	})
	req := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(string(body)))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-GitHub-Delivery", "abc-1")
	req.Header.Set("X-Hub-Signature-256", sign(body, "shhh"))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", w.Result().StatusCode, w.Body.String())
	}

	// enqueued_jobs row should exist for the idempotency key.
	got, err := stores.Jobs.GetByKey(context.Background(), "run:1234:7:h")
	if err != nil {
		t.Fatalf("enqueued_jobs not found: %v", err)
	}
	if got.JobType != "RunPR" {
		t.Fatalf("expected RunPR, got %s", got.JobType)
	}

	// github_webhook_log row should exist.
	wh, err := stores.WebhookLog.Get(context.Background(), "abc-1")
	if err != nil {
		t.Fatalf("webhook log row missing: %v", err)
	}
	if wh.EventType != "pull_request" {
		t.Fatalf("event_type=%q", wh.EventType)
	}

	// Redelivery is a no-op (202 + no new row).
	req2 := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(string(body)))
	req2.Header.Set("X-GitHub-Event", "pull_request")
	req2.Header.Set("X-GitHub-Delivery", "abc-1")
	req2.Header.Set("X-Hub-Signature-256", sign(body, "shhh"))
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	if w2.Result().StatusCode != http.StatusAccepted {
		t.Fatalf("redelivery status=%d", w2.Result().StatusCode)
	}
}

// Sanity: making sure the package reference doesn't get pruned by an
// over-eager lint pass.
var _ = github.SummaryMarker
