package github

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/diffsec/quokka/internal/store"
)

// EnqueueFunc is what the webhook dispatch calls to schedule a job. The
// caller wires this to the worker queue.
type EnqueueFunc func(ctx context.Context, jobType string, payload any, idempotencyKey string) (newlyEnqueued bool, err error)

// WebhookHandler verifies + dispatches GitHub webhook payloads.
//
// HMAC-SHA256 of the raw body with the configured secret must equal the
// X-Hub-Signature-256 header. The raw payload is persisted to
// github_webhook_log for replay and audit before dispatch.
type WebhookHandler struct {
	Secret  string
	Stores  *store.Stores
	Enqueue EnqueueFunc
}

// RunPRPayload is the job payload for RunPR and RunManual.
type RunPRPayload struct {
	InstallationID int64  `json:"installation_id"`
	RepoFullName   string `json:"repo_full_name"`
	GitHubRepoID   int64  `json:"github_repo_id"`
	PRNumber       int    `json:"pr_number"`
	BaseSHA        string `json:"base_sha"`
	HeadSHA        string `json:"head_sha"`
	CommitsCount   int    `json:"commits_count"`
	Trigger        string `json:"trigger"`
}

// InstallRepoPayload is the job payload for InstallRepo.
type InstallRepoPayload struct {
	InstallationID int64  `json:"installation_id"`
	RepoFullName   string `json:"repo_full_name"`
	GitHubRepoID   int64  `json:"github_repo_id"`
}

// VerifySignature returns nil when the body matches the HMAC header.
func (h *WebhookHandler) VerifySignature(body []byte, headerSig string) error {
	if h.Secret == "" {
		return errors.New("webhook: secret not configured")
	}
	if !strings.HasPrefix(headerSig, "sha256=") {
		return errors.New("webhook: missing or malformed X-Hub-Signature-256")
	}
	want := strings.TrimPrefix(headerSig, "sha256=")
	mac := hmac.New(sha256.New, []byte(h.Secret))
	mac.Write(body)
	got := hex.EncodeToString(mac.Sum(nil))
	// constant-time compare
	if !hmac.Equal([]byte(want), []byte(got)) {
		return errors.New("webhook: signature mismatch")
	}
	return nil
}

// ServeHTTP is the entrypoint wired at POST /webhooks/github.
func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20)) // cap at 8 MiB
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	sig := r.Header.Get("X-Hub-Signature-256")
	if err := h.VerifySignature(body, sig); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	deliveryID := r.Header.Get("X-GitHub-Delivery")
	eventType := r.Header.Get("X-GitHub-Event")

	// Persist raw payload before dispatch.
	if h.Stores != nil && h.Stores.WebhookLog != nil {
		action := pluckJSONString(body, "action")
		_ = h.Stores.WebhookLog.Append(r.Context(), &store.GitHubWebhookLog{
			DeliveryID:  deliveryID,
			EventType:   eventType,
			Action:      action,
			PayloadJSON: string(body),
			Signature:   sig,
		})
	}

	dispatchErr := h.Dispatch(r.Context(), eventType, body)
	if h.Stores != nil && h.Stores.WebhookLog != nil && deliveryID != "" {
		msg := ""
		if dispatchErr != nil {
			msg = dispatchErr.Error()
		}
		_ = h.Stores.WebhookLog.MarkProcessed(r.Context(), deliveryID, msg)
	}
	if dispatchErr != nil {
		http.Error(w, dispatchErr.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// Dispatch decodes the event type-specific subset of the payload and
// enqueues the corresponding job. Unknown event types are ignored (no-op).
func (h *WebhookHandler) Dispatch(ctx context.Context, eventType string, body []byte) error {
	switch eventType {
	case "ping":
		return nil
	case "pull_request":
		return h.dispatchPR(ctx, body)
	case "check_run":
		return h.dispatchCheckRun(ctx, body)
	case "installation":
		return h.dispatchInstallation(ctx, body)
	case "installation_repositories":
		return h.dispatchInstallationRepos(ctx, body)
	default:
		return nil
	}
}

// prEvent picks the only fields we need from `pull_request` deliveries.
type prEvent struct {
	Action      string `json:"action"`
	Number      int    `json:"number"`
	PullRequest struct {
		Commits int `json:"commits"`
		Base    struct {
			SHA string `json:"sha"`
		} `json:"base"`
		Head struct {
			SHA string `json:"sha"`
		} `json:"head"`
	} `json:"pull_request"`
	Repository struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
	} `json:"repository"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
}

func (h *WebhookHandler) dispatchPR(ctx context.Context, body []byte) error {
	var e prEvent
	if err := json.Unmarshal(body, &e); err != nil {
		return fmt.Errorf("pull_request decode: %w", err)
	}
	switch e.Action {
	case "opened", "synchronize", "reopened":
	default:
		return nil
	}
	if e.Repository.ID == 0 || e.Number == 0 || e.PullRequest.Head.SHA == "" {
		return errors.New("pull_request: missing fields")
	}
	key := fmt.Sprintf("run:%d:%d:%s", e.Repository.ID, e.Number, e.PullRequest.Head.SHA)
	payload := RunPRPayload{
		InstallationID: e.Installation.ID,
		RepoFullName:   e.Repository.FullName,
		GitHubRepoID:   e.Repository.ID,
		PRNumber:       e.Number,
		BaseSHA:        e.PullRequest.Base.SHA,
		HeadSHA:        e.PullRequest.Head.SHA,
		CommitsCount:   e.PullRequest.Commits,
		Trigger:        "pr_" + e.Action,
	}
	if h.Enqueue == nil {
		return nil
	}
	_, err := h.Enqueue(ctx, "RunPR", payload, key)
	return err
}

type checkRunEvent struct {
	Action   string `json:"action"`
	CheckRun struct {
		HeadSHA    string `json:"head_sha"`
		ExternalID string `json:"external_id"`
		PullRequests []struct {
			Number int `json:"number"`
			Base   struct {
				SHA string `json:"sha"`
			} `json:"base"`
			Head struct {
				SHA string `json:"sha"`
			} `json:"head"`
		} `json:"pull_requests"`
	} `json:"check_run"`
	Repository struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
	} `json:"repository"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
}

func (h *WebhookHandler) dispatchCheckRun(ctx context.Context, body []byte) error {
	var e checkRunEvent
	if err := json.Unmarshal(body, &e); err != nil {
		return fmt.Errorf("check_run decode: %w", err)
	}
	if e.Action != "rerequested" {
		return nil
	}
	if len(e.CheckRun.PullRequests) == 0 {
		return nil
	}
	pr := e.CheckRun.PullRequests[0]
	key := fmt.Sprintf("run:%d:%d:%s", e.Repository.ID, pr.Number, pr.Head.SHA)
	payload := RunPRPayload{
		InstallationID: e.Installation.ID,
		RepoFullName:   e.Repository.FullName,
		GitHubRepoID:   e.Repository.ID,
		PRNumber:       pr.Number,
		BaseSHA:        pr.Base.SHA,
		HeadSHA:        pr.Head.SHA,
		Trigger:        "rerun",
	}
	if h.Enqueue == nil {
		return nil
	}
	_, err := h.Enqueue(ctx, "RunManual", payload, key)
	return err
}

type installEvent struct {
	Action       string `json:"action"`
	Installation struct {
		ID      int64 `json:"id"`
		Account struct {
			Login string `json:"login"`
		} `json:"account"`
	} `json:"installation"`
	Repositories []struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
	} `json:"repositories"`
}

func (h *WebhookHandler) dispatchInstallation(ctx context.Context, body []byte) error {
	var e installEvent
	if err := json.Unmarshal(body, &e); err != nil {
		return fmt.Errorf("installation decode: %w", err)
	}
	if e.Action != "created" {
		return nil
	}
	if h.Enqueue == nil {
		return nil
	}
	for _, repo := range e.Repositories {
		key := fmt.Sprintf("install:%d", repo.ID)
		if _, err := h.Enqueue(ctx, "InstallRepo", InstallRepoPayload{
			InstallationID: e.Installation.ID,
			RepoFullName:   repo.FullName,
			GitHubRepoID:   repo.ID,
		}, key); err != nil {
			return err
		}
	}
	return nil
}

type installReposEvent struct {
	Action       string `json:"action"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
	RepositoriesAdded []struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
	} `json:"repositories_added"`
	RepositoriesRemoved []struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
	} `json:"repositories_removed"`
}

func (h *WebhookHandler) dispatchInstallationRepos(ctx context.Context, body []byte) error {
	var e installReposEvent
	if err := json.Unmarshal(body, &e); err != nil {
		return fmt.Errorf("installation_repositories decode: %w", err)
	}
	if e.Action != "added" {
		return nil
	}
	if h.Enqueue == nil {
		return nil
	}
	for _, repo := range e.RepositoriesAdded {
		key := fmt.Sprintf("install:%d", repo.ID)
		if _, err := h.Enqueue(ctx, "InstallRepo", InstallRepoPayload{
			InstallationID: e.Installation.ID,
			RepoFullName:   repo.FullName,
			GitHubRepoID:   repo.ID,
		}, key); err != nil {
			return err
		}
	}
	return nil
}

// pluckJSONString reads a top-level string field from raw JSON without
// allocating the whole struct. Used to extract the "action" for the audit
// row before full decode.
func pluckJSONString(body []byte, key string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return ""
	}
	return s
}
