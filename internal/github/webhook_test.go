package github_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/diffsec/quokka/internal/github"
)

type recordedJob struct {
	JobType string
	Payload any
	Key     string
}

type recordingEnqueuer struct {
	mu   sync.Mutex
	jobs []recordedJob
	seen map[string]bool
}

func newRecording() *recordingEnqueuer {
	return &recordingEnqueuer{seen: map[string]bool{}}
}

func (r *recordingEnqueuer) Enqueue(ctx context.Context, jobType string, payload any, key string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen[key] {
		return false, nil
	}
	r.seen[key] = true
	r.jobs = append(r.jobs, recordedJob{JobType: jobType, Payload: payload, Key: key})
	return true, nil
}

func sign(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySignatureGoodBadMissing(t *testing.T) {
	h := &github.WebhookHandler{Secret: "topsecret"}
	body := []byte(`{"hello":"world"}`)
	if err := h.VerifySignature(body, sign(body, "topsecret")); err != nil {
		t.Fatalf("good signature should pass: %v", err)
	}
	if err := h.VerifySignature(body, sign(body, "wrong")); err == nil {
		t.Fatalf("bad signature should fail")
	}
	if err := h.VerifySignature(body, ""); err == nil {
		t.Fatalf("missing signature should fail")
	}
}

func TestDispatchPROpenedEnqueuesRunPR(t *testing.T) {
	rec := newRecording()
	h := &github.WebhookHandler{Secret: "s", Enqueue: rec.Enqueue}
	payload := map[string]any{
		"action": "opened",
		"number": 7,
		"pull_request": map[string]any{
			"commits": 3,
			"base":    map[string]any{"sha": "base-sha"},
			"head":    map[string]any{"sha": "head-sha"},
		},
		"repository":   map[string]any{"id": 1234, "full_name": "acme/widget"},
		"installation": map[string]any{"id": 99},
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(string(body)))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-GitHub-Delivery", "abc-1")
	req.Header.Set("X-Hub-Signature-256", sign(body, "s"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", w.Result().StatusCode, w.Body.String())
	}
	if len(rec.jobs) != 1 {
		t.Fatalf("expected one job, got %d", len(rec.jobs))
	}
	if rec.jobs[0].JobType != "RunPR" {
		t.Fatalf("expected RunPR, got %s", rec.jobs[0].JobType)
	}
	if rec.jobs[0].Key != "run:1234:7:head-sha" {
		t.Fatalf("unexpected idempotency key %q", rec.jobs[0].Key)
	}
}

func TestDispatchPRSynchronizeRedeliveryIsNoOp(t *testing.T) {
	rec := newRecording()
	h := &github.WebhookHandler{Secret: "s", Enqueue: rec.Enqueue}
	payload := map[string]any{
		"action": "synchronize",
		"number": 7,
		"pull_request": map[string]any{
			"base": map[string]any{"sha": "b"},
			"head": map[string]any{"sha": "h"},
		},
		"repository":   map[string]any{"id": 9, "full_name": "x/y"},
		"installation": map[string]any{"id": 1},
	}
	body, _ := json.Marshal(payload)
	req1 := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(string(body)))
	req1.Header.Set("X-GitHub-Event", "pull_request")
	req1.Header.Set("X-Hub-Signature-256", sign(body, "s"))
	h.ServeHTTP(httptest.NewRecorder(), req1)

	req2 := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(string(body)))
	req2.Header.Set("X-GitHub-Event", "pull_request")
	req2.Header.Set("X-Hub-Signature-256", sign(body, "s"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req2)

	if w.Result().StatusCode != http.StatusAccepted {
		t.Fatalf("redelivery should still 202: %d", w.Result().StatusCode)
	}
	if len(rec.jobs) != 1 {
		t.Fatalf("expected exactly one job after redelivery, got %d", len(rec.jobs))
	}
}

func TestDispatchInstallationCreatedEnqueuesPerRepo(t *testing.T) {
	rec := newRecording()
	h := &github.WebhookHandler{Secret: "s", Enqueue: rec.Enqueue}
	payload := map[string]any{
		"action": "created",
		"installation": map[string]any{
			"id":      55,
			"account": map[string]any{"login": "acme"},
		},
		"repositories": []map[string]any{
			{"id": 1, "full_name": "acme/a"},
			{"id": 2, "full_name": "acme/b"},
		},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(string(body)))
	req.Header.Set("X-GitHub-Event", "installation")
	req.Header.Set("X-Hub-Signature-256", sign(body, "s"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", w.Result().StatusCode, w.Body.String())
	}
	if len(rec.jobs) != 2 {
		t.Fatalf("expected 2 jobs, got %d", len(rec.jobs))
	}
	for _, j := range rec.jobs {
		if j.JobType != "InstallRepo" {
			t.Fatalf("unexpected jobType %s", j.JobType)
		}
	}
}

func TestServeHTTPRejectsBadSig(t *testing.T) {
	h := &github.WebhookHandler{Secret: "s"}
	body := []byte(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(string(body)))
	req.Header.Set("X-GitHub-Event", "ping")
	req.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Result().StatusCode)
	}
}
