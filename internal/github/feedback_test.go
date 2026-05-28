package github_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/diffsec/quokka/internal/github"
	"github.com/diffsec/quokka/internal/store"
)

type fakeFeedback struct {
	mu              sync.Mutex
	calls           []string
	finishConcl     string
	postedComments  []github.ReviewComment
	summaryBody     string
	dismissedReview int64
	upsertedID      int64
	createdReview   int64
}

func (f *fakeFeedback) StartCheckRun(ctx context.Context, owner, repo, head, name, url, ext string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "start_check_run")
	return 11, nil
}
func (f *fakeFeedback) FinishCheckRun(ctx context.Context, owner, repo string, id int64, concl, title, summary string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "finish_check_run")
	f.finishConcl = concl
	return nil
}
func (f *fakeFeedback) PostReview(ctx context.Context, owner, repo string, pr int, head, body string, comments []github.ReviewComment) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "post_review")
	f.postedComments = comments
	f.createdReview = 22
	return 22, nil
}
func (f *fakeFeedback) DismissReview(ctx context.Context, owner, repo string, pr int, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "dismiss_review")
	f.dismissedReview = id
	return nil
}
func (f *fakeFeedback) UpsertSummaryComment(ctx context.Context, owner, repo string, pr int, body string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "upsert_summary_comment")
	f.summaryBody = body
	f.upsertedID = 33
	return 33, nil
}

func TestPostRunFeedbackCallsInRightOrder(t *testing.T) {
	fc := &fakeFeedback{}
	settings := &store.PRFeedbackSettings{
		CheckRunEnabled:       true,
		InlineCommentsEnabled: true,
		SummaryCommentEnabled: true,
	}
	inline := []github.ReviewComment{{Path: "foo.go", Position: 2, Body: "bad"}}
	order, revID, commentID, err := github.PostRunFeedback(
		context.Background(), fc, settings,
		"acme", "widget", 7, "head", 11, 0,
		"action_required", "title", "summary",
		inline,
	)
	if err != nil {
		t.Fatalf("PostRunFeedback: %v", err)
	}
	if revID != 22 || commentID != 33 {
		t.Fatalf("revID=%d commentID=%d", revID, commentID)
	}
	if len(order) != 3 || order[0] != "check_run" || order[1] != "review" || order[2] != "summary_comment" {
		t.Fatalf("order=%v", order)
	}
	if !strings.Contains(fc.summaryBody, github.SummaryMarker) {
		t.Fatalf("summary body missing marker: %q", fc.summaryBody)
	}
}

func TestPostRunFeedbackDismissesPriorReviewOnRerun(t *testing.T) {
	fc := &fakeFeedback{}
	settings := &store.PRFeedbackSettings{
		CheckRunEnabled:       true,
		InlineCommentsEnabled: true,
		SummaryCommentEnabled: true,
	}
	inline := []github.ReviewComment{{Path: "x.go", Position: 1, Body: "issue"}}
	_, _, _, err := github.PostRunFeedback(context.Background(), fc, settings,
		"a", "b", 1, "h", 11, 88, "neutral", "t", "s", inline)
	if err != nil {
		t.Fatalf("PostRunFeedback: %v", err)
	}
	if fc.dismissedReview != 88 {
		t.Fatalf("expected dismissed review=88, got %d", fc.dismissedReview)
	}
	// dismiss_review should come before post_review.
	dismissIdx := -1
	postIdx := -1
	for i, c := range fc.calls {
		if c == "dismiss_review" {
			dismissIdx = i
		}
		if c == "post_review" {
			postIdx = i
		}
	}
	if dismissIdx == -1 || postIdx == -1 || dismissIdx > postIdx {
		t.Fatalf("dismiss should precede post: calls=%v", fc.calls)
	}
}

func TestConclusionMapping(t *testing.T) {
	cases := []struct {
		findings []github.Finding
		want     string
	}{
		{nil, "success"},
		{[]github.Finding{{Severity: "high"}}, "action_required"},
		{[]github.Finding{{Severity: "critical"}, {Severity: "low"}}, "action_required"},
		{[]github.Finding{{Severity: "medium"}}, "neutral"},
		{[]github.Finding{{Severity: "low"}}, "neutral"},
	}
	for _, tc := range cases {
		got := github.ConclusionForFindings(tc.findings)
		if got != tc.want {
			t.Errorf("ConclusionForFindings(%v) = %s, want %s", tc.findings, got, tc.want)
		}
	}
}
