// Package handlers — findings triage actions.
//
// Each action has a GET partial that opens a modal (CSRF token included)
// plus a POST that persists the change and re-renders the affected row.
// Bulk action takes form-encoded ids[]=...&action=... and runs each action
// in a single transaction.
package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/diffsec/quokka/internal/exception"
	"github.com/diffsec/quokka/internal/finding"
	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/web/templates"
	"github.com/diffsec/quokka/internal/web/webctx"
)

// TriageHandler bundles every per-finding action: dismiss, suppress, snooze,
// add-note, reopen, and bulk.
type TriageHandler struct {
	Stores *store.Stores
}

// ----- modal partials (GET) ---------------------------------------------------

func (h *TriageHandler) DismissModal(w http.ResponseWriter, r *http.Request) {
	repoID, findingID := r.PathValue("repo_id"), r.PathValue("finding_id")
	renderHTML(w, r, templates.DismissModal(templates.ModalView{
		RepoID:    repoID,
		FindingID: findingID,
		CSRFToken: webctx.CSRFTokenFromCtx(r.Context()),
	}))
}

func (h *TriageHandler) SuppressModal(w http.ResponseWriter, r *http.Request) {
	repoID, findingID := r.PathValue("repo_id"), r.PathValue("finding_id")
	// Pre-fill axis values from the finding (fingerprint, file, cwe).
	var prefill templates.SuppressPrefill
	if row, err := h.Stores.Findings.Get(r.Context(), findingID); err == nil {
		prefill = templates.SuppressPrefill{
			Fingerprint: row.Fingerprint,
			PathGlob:    row.File,
			CWE:         row.CWE,
		}
	}
	renderHTML(w, r, templates.SuppressModal(templates.ModalView{
		RepoID:    repoID,
		FindingID: findingID,
		CSRFToken: webctx.CSRFTokenFromCtx(r.Context()),
		Suppress:  prefill,
	}))
}

func (h *TriageHandler) SnoozeModal(w http.ResponseWriter, r *http.Request) {
	repoID, findingID := r.PathValue("repo_id"), r.PathValue("finding_id")
	renderHTML(w, r, templates.SnoozeModal(templates.ModalView{
		RepoID:    repoID,
		FindingID: findingID,
		CSRFToken: webctx.CSRFTokenFromCtx(r.Context()),
		DefaultUntil: time.Now().AddDate(0, 0, 14).Format("2006-01-02"),
	}))
}

func (h *TriageHandler) NoteModal(w http.ResponseWriter, r *http.Request) {
	repoID, findingID := r.PathValue("repo_id"), r.PathValue("finding_id")
	renderHTML(w, r, templates.NoteModal(templates.ModalView{
		RepoID:    repoID,
		FindingID: findingID,
		CSRFToken: webctx.CSRFTokenFromCtx(r.Context()),
	}))
}

// ----- action handlers (POST) -------------------------------------------------

func (h *TriageHandler) Dismiss(w http.ResponseWriter, r *http.Request) {
	repoID, findingID := r.PathValue("repo_id"), r.PathValue("finding_id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	reason := r.PostForm.Get("reason")
	if err := h.dismissOne(r.Context(), repoID, findingID, reason, actorID(r)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	triageRedirect(w, r, repoID, findingID)
}

func (h *TriageHandler) Suppress(w http.ResponseWriter, r *http.Request) {
	repoID, findingID := r.PathValue("repo_id"), r.PathValue("finding_id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	axis := r.PostForm.Get("axis")
	value := r.PostForm.Get("value")
	reason := r.PostForm.Get("reason")
	expiresStr := r.PostForm.Get("expires")
	if reason == "" {
		http.Error(w, "reason is required", http.StatusBadRequest)
		return
	}
	expires := time.Now().AddDate(0, 0, 90)
	if expiresStr != "" {
		if t, err := time.Parse("2006-01-02", expiresStr); err == nil {
			expires = t
		}
	}
	req := exception.AddRequest{
		RepoID:     repoID,
		Reason:     reason,
		Expires:    expires,
		ApprovedBy: actorLogin(r),
	}
	switch axis {
	case "fingerprint":
		req.Fingerprint = value
	case "path_glob":
		req.PathGlob = value
	case "cwe":
		req.CWE = value
	case "agent_name":
		req.AgentName = value
	default:
		http.Error(w, "invalid axis", http.StatusBadRequest)
		return
	}
	if _, err := exception.Add(r.Context(), h.Stores.Exceptions, req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Also record an action on the finding row so the activity log shows it.
	_ = h.Stores.FindingActions.Append(r.Context(), findingID, "suppress", actorID(r), reason, fmt.Sprintf(`{"axis":%q,"value":%q}`, axis, value))
	triageRedirect(w, r, repoID, findingID)
}

func (h *TriageHandler) Snooze(w http.ResponseWriter, r *http.Request) {
	repoID, findingID := r.PathValue("repo_id"), r.PathValue("finding_id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	untilStr := r.PostForm.Get("until")
	reason := r.PostForm.Get("reason")
	if untilStr == "" {
		http.Error(w, "until is required", http.StatusBadRequest)
		return
	}
	until, err := time.Parse("2006-01-02", untilStr)
	if err != nil {
		http.Error(w, "bad until: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.Stores.Findings.UpdateStatus(r.Context(), findingID, "snoozed"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	payload := fmt.Sprintf(`{"until":%q}`, until.Format("2006-01-02"))
	_ = h.Stores.FindingActions.Append(r.Context(), findingID, "snooze", actorID(r), reason, payload)
	triageRedirect(w, r, repoID, findingID)
}

func (h *TriageHandler) AddNote(w http.ResponseWriter, r *http.Request) {
	repoID, findingID := r.PathValue("repo_id"), r.PathValue("finding_id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	text := r.PostForm.Get("text")
	if strings.TrimSpace(text) == "" {
		http.Error(w, "text required", http.StatusBadRequest)
		return
	}
	if _, err := finding.UpdateNote(r.Context(), h.Stores.Findings, finding.UpdateNoteRequest{
		ID:     findingID,
		Author: actorLogin(r),
		Text:   text,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = h.Stores.FindingActions.Append(r.Context(), findingID, "note", actorID(r), text, "")
	triageRedirect(w, r, repoID, findingID)
}

func (h *TriageHandler) Reopen(w http.ResponseWriter, r *http.Request) {
	repoID, findingID := r.PathValue("repo_id"), r.PathValue("finding_id")
	row, err := h.Stores.Findings.Get(r.Context(), findingID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	row.Status = "open"
	row.ReopenedCount++
	if err := h.Stores.Findings.Update(r.Context(), row); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = h.Stores.FindingActions.Append(r.Context(), findingID, "reopen", actorID(r), "", "")
	triageRedirect(w, r, repoID, findingID)
}

func (h *TriageHandler) Bulk(w http.ResponseWriter, r *http.Request) {
	repoID := r.PathValue("repo_id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ids := r.PostForm["ids[]"]
	if len(ids) == 0 {
		// Fallback: some clients send ids without brackets.
		ids = r.PostForm["ids"]
	}
	action := r.PostForm.Get("action")
	reason := r.PostForm.Get("reason")
	if len(ids) == 0 || action == "" {
		http.Error(w, "ids[] and action required", http.StatusBadRequest)
		return
	}

	// Run the batch as a single SQL transaction. We grab the *sql.DB from
	// stores.DB and do raw UPDATE/INSERT statements. This sidesteps the
	// per-store helpers that open their own statements.
	tx, err := h.Stores.DB.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC()
	var statusUpdate string
	switch action {
	case "dismiss":
		statusUpdate = "false_positive"
	case "snooze":
		statusUpdate = "snoozed"
	case "reopen":
		statusUpdate = "open"
	default:
		http.Error(w, "unsupported bulk action", http.StatusBadRequest)
		return
	}
	for _, id := range ids {
		if _, err := tx.ExecContext(r.Context(),
			`UPDATE findings SET status=?, updated_at=? WHERE id=? AND repo_id=?`,
			statusUpdate, now, id, repoID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Best-effort action log outside the transaction.
	for _, id := range ids {
		_ = h.Stores.FindingActions.Append(r.Context(), id, action, actorID(r), reason, "")
	}
	http.Redirect(w, r, "/repos/"+repoID+"/findings", http.StatusSeeOther)
}

// ----- helpers ---------------------------------------------------------------

func (h *TriageHandler) dismissOne(ctx context.Context, repoID, findingID, reason, actor string) error {
	row, err := h.Stores.Findings.Get(ctx, findingID)
	if err != nil {
		return err
	}
	if row.RepoID != repoID {
		return errors.New("finding does not belong to repo")
	}
	if err := h.Stores.Findings.UpdateStatus(ctx, findingID, "false_positive"); err != nil {
		return err
	}
	return h.Stores.FindingActions.Append(ctx, findingID, "dismiss", actor, reason, "")
}

func actorID(r *http.Request) string {
	if u := webctx.UserFromCtx(r.Context()); u != nil {
		return u.ID
	}
	return ""
}

func actorLogin(r *http.Request) string {
	if u := webctx.UserFromCtx(r.Context()); u != nil {
		return u.GitHubLogin
	}
	return "system"
}

func triageRedirect(w http.ResponseWriter, r *http.Request, repoID, findingID string) {
	// HTMX requests: respond with HX-Redirect or a refresh hint. For now we
	// 303-redirect to the finding's detail page; HTMX follows redirects.
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/repos/"+repoID+"/findings/"+findingID)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, "/repos/"+repoID+"/findings/"+findingID, http.StatusSeeOther)
}
