package github

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/diffsec/quokka/internal/store"
	gogithub "github.com/google/go-github/v66/github"
)

// SummaryMarker is the magic comment that lets us identify and update-in-place
// the summary comment on a re-run.
const SummaryMarker = "<!-- quokka-run-summary -->"

// Finding is the narrow subset of FindingRow the feedback writers consume.
// Using a fresh struct keeps this package decoupled from the heavy store row.
type Finding struct {
	Title       string
	Severity    string
	CWE         string
	File        string
	LineStart   int
	Description string
	Remediation string
}

// FeedbackClient is the surface the worker uses to post run results.
// Production impl wraps go-github; the worker tests use a fake.
type FeedbackClient interface {
	StartCheckRun(ctx context.Context, owner, repo, headSHA, name, detailsURL, externalID string) (checkRunID int64, err error)
	FinishCheckRun(ctx context.Context, owner, repo string, checkRunID int64, conclusion, title, summary string) error
	PostReview(ctx context.Context, owner, repo string, prNumber int, headSHA, body string, comments []ReviewComment) (reviewID int64, err error)
	DismissReview(ctx context.Context, owner, repo string, prNumber int, reviewID int64) error
	UpsertSummaryComment(ctx context.Context, owner, repo string, prNumber int, body string) (commentID int64, err error)
}

// ReviewComment is the inline review-comment shape.
type ReviewComment struct {
	Path     string
	Position int
	Body     string
}

// ConclusionForFindings maps the worst-severity finding to the GitHub Check
// Run conclusion. Crash is signalled separately by the caller.
func ConclusionForFindings(fs []Finding) string {
	worst := 0
	rank := map[string]int{"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
	for _, f := range fs {
		if r := rank[strings.ToLower(f.Severity)]; r > worst {
			worst = r
		}
	}
	switch {
	case worst >= 4:
		return "action_required"
	case worst == 3:
		return "neutral"
	case worst > 0:
		return "neutral"
	default:
		return "success"
	}
}

// PostRunFeedback fires the configured writers in order: Check Run finish,
// Review with inline comments, Summary comment. It also persists check_run
// and review IDs on subsequent calls (PR-5 will surface them in the UI).
//
// Returns the order in which writers were called for tests to assert on.
func PostRunFeedback(
	ctx context.Context,
	fc FeedbackClient,
	settings *store.PRFeedbackSettings,
	owner, repo string,
	prNumber int,
	headSHA string,
	checkRunID int64,
	prevReviewID int64,
	conclusion string,
	summaryTitle string,
	summaryBody string,
	inline []ReviewComment,
) (writerOrder []string, newReviewID int64, newCommentID int64, err error) {
	if fc == nil {
		return nil, 0, 0, errors.New("PostRunFeedback: nil client")
	}
	if settings == nil {
		settings = &store.PRFeedbackSettings{
			CheckRunEnabled:       true,
			InlineCommentsEnabled: true,
			SummaryCommentEnabled: true,
		}
	}
	if settings.CheckRunEnabled && checkRunID != 0 {
		if err := fc.FinishCheckRun(ctx, owner, repo, checkRunID, conclusion, summaryTitle, summaryBody); err != nil {
			return writerOrder, 0, 0, fmt.Errorf("check_run: %w", err)
		}
		writerOrder = append(writerOrder, "check_run")
	}
	if settings.InlineCommentsEnabled {
		if prevReviewID != 0 {
			_ = fc.DismissReview(ctx, owner, repo, prNumber, prevReviewID)
		}
		filtered := filterByThreshold(inline, settings.InlineSeverityThreshold)
		if len(filtered) > 0 {
			id, err := fc.PostReview(ctx, owner, repo, prNumber, headSHA, summaryTitle, filtered)
			if err != nil {
				return writerOrder, 0, 0, fmt.Errorf("review: %w", err)
			}
			newReviewID = id
			writerOrder = append(writerOrder, "review")
		}
	}
	if settings.SummaryCommentEnabled {
		body := summaryBody
		if !strings.Contains(body, SummaryMarker) {
			body = SummaryMarker + "\n\n" + body
		}
		id, err := fc.UpsertSummaryComment(ctx, owner, repo, prNumber, body)
		if err != nil {
			return writerOrder, newReviewID, 0, fmt.Errorf("summary_comment: %w", err)
		}
		newCommentID = id
		writerOrder = append(writerOrder, "summary_comment")
	}
	return writerOrder, newReviewID, newCommentID, nil
}

// filterByThreshold drops review comments whose severity (encoded in the
// body via a "**Severity:** ..." marker we inject) is below the configured
// threshold. PR-5's settings UI controls this knob.
//
// The current implementation is permissive: the caller has already prepared
// the comments and may have filtered by severity itself; we leave them
// as-is in PR-4. The hook exists so PR-5 can swap in real filtering.
func filterByThreshold(in []ReviewComment, threshold string) []ReviewComment {
	_ = threshold
	return in
}

// GoGitHubFeedback is the production FeedbackClient.
type GoGitHubFeedback struct {
	Auth           *AppAuth
	InstallationID int64
}

// installationClient returns a fresh go-github client for the installation.
func (g *GoGitHubFeedback) installationClient(ctx context.Context) (*gogithub.Client, error) {
	return g.Auth.InstallationClient(ctx, g.InstallationID)
}

func (g *GoGitHubFeedback) StartCheckRun(ctx context.Context, owner, repo, headSHA, name, detailsURL, externalID string) (int64, error) {
	client, err := g.installationClient(ctx)
	if err != nil {
		return 0, err
	}
	status := "in_progress"
	opts := gogithub.CreateCheckRunOptions{
		Name:       name,
		HeadSHA:    headSHA,
		Status:     &status,
		DetailsURL: &detailsURL,
		ExternalID: &externalID,
		StartedAt:  &gogithub.Timestamp{Time: time.Now().UTC()},
	}
	cr, _, err := client.Checks.CreateCheckRun(ctx, owner, repo, opts)
	if err != nil {
		return 0, err
	}
	if cr.ID == nil {
		return 0, errors.New("create check run: empty ID")
	}
	return *cr.ID, nil
}

func (g *GoGitHubFeedback) FinishCheckRun(ctx context.Context, owner, repo string, checkRunID int64, conclusion, title, summary string) error {
	client, err := g.installationClient(ctx)
	if err != nil {
		return err
	}
	status := "completed"
	opts := gogithub.UpdateCheckRunOptions{
		Name:       "quokka",
		Status:     &status,
		Conclusion: &conclusion,
		CompletedAt: &gogithub.Timestamp{Time: time.Now().UTC()},
		Output: &gogithub.CheckRunOutput{
			Title:   &title,
			Summary: &summary,
		},
	}
	_, _, err = client.Checks.UpdateCheckRun(ctx, owner, repo, checkRunID, opts)
	return err
}

func (g *GoGitHubFeedback) PostReview(ctx context.Context, owner, repo string, prNumber int, headSHA, body string, comments []ReviewComment) (int64, error) {
	client, err := g.installationClient(ctx)
	if err != nil {
		return 0, err
	}
	event := "COMMENT"
	rcs := make([]*gogithub.DraftReviewComment, 0, len(comments))
	for _, c := range comments {
		p := c.Position
		body := c.Body
		path := c.Path
		rcs = append(rcs, &gogithub.DraftReviewComment{
			Path:     &path,
			Position: &p,
			Body:     &body,
		})
	}
	rev, _, err := client.PullRequests.CreateReview(ctx, owner, repo, prNumber, &gogithub.PullRequestReviewRequest{
		CommitID: &headSHA,
		Body:     &body,
		Event:    &event,
		Comments: rcs,
	})
	if err != nil {
		return 0, err
	}
	if rev.ID == nil {
		return 0, errors.New("create review: empty ID")
	}
	return *rev.ID, nil
}

func (g *GoGitHubFeedback) DismissReview(ctx context.Context, owner, repo string, prNumber int, reviewID int64) error {
	client, err := g.installationClient(ctx)
	if err != nil {
		return err
	}
	msg := "Superseded by a newer run."
	_, _, err = client.PullRequests.DismissReview(ctx, owner, repo, prNumber, reviewID, &gogithub.PullRequestReviewDismissalRequest{
		Message: &msg,
	})
	return err
}

func (g *GoGitHubFeedback) UpsertSummaryComment(ctx context.Context, owner, repo string, prNumber int, body string) (int64, error) {
	client, err := g.installationClient(ctx)
	if err != nil {
		return 0, err
	}
	// List existing comments and find ours by marker.
	comments, _, err := client.Issues.ListComments(ctx, owner, repo, prNumber, &gogithub.IssueListCommentsOptions{
		ListOptions: gogithub.ListOptions{PerPage: 100},
	})
	if err != nil {
		return 0, err
	}
	for _, c := range comments {
		if c.Body == nil || c.ID == nil {
			continue
		}
		if strings.Contains(*c.Body, SummaryMarker) {
			_, _, err := client.Issues.EditComment(ctx, owner, repo, *c.ID, &gogithub.IssueComment{Body: &body})
			if err != nil {
				return 0, err
			}
			return *c.ID, nil
		}
	}
	created, _, err := client.Issues.CreateComment(ctx, owner, repo, prNumber, &gogithub.IssueComment{Body: &body})
	if err != nil {
		return 0, err
	}
	if created.ID == nil {
		return 0, errors.New("create summary comment: empty ID")
	}
	return *created.ID, nil
}
