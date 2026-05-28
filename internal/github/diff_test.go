package github_test

import (
	"strings"
	"testing"

	"github.com/diffsec/quokka/internal/github"
)

// A small canned `git diff --unified=0` covering one file with two hunks.
const sampleDiff = `diff --git a/foo.go b/foo.go
index 1111111..2222222 100644
--- a/foo.go
+++ b/foo.go
@@ -10,0 +11,2 @@ func a() {
+	added1
+	added2
@@ -20,0 +30,1 @@ func b() {
+	added3
`

func TestParseUnifiedDiffBuildsHunks(t *testing.T) {
	d, err := github.ParseUnifiedDiff(strings.NewReader(sampleDiff))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	hunks, ok := d["foo.go"]
	if !ok {
		t.Fatalf("expected hunks for foo.go, got %#v", d)
	}
	if len(hunks) != 2 {
		t.Fatalf("expected 2 hunks, got %d", len(hunks))
	}
	if hunks[0].StartLine != 11 || hunks[0].Length < 1 {
		t.Fatalf("first hunk wrong: %+v", hunks[0])
	}
	if hunks[1].StartLine != 30 || hunks[1].Length < 1 {
		t.Fatalf("second hunk wrong: %+v", hunks[1])
	}
}

func TestPositionForLineHitsAndMisses(t *testing.T) {
	d, _ := github.ParseUnifiedDiff(strings.NewReader(sampleDiff))

	cases := []struct {
		file   string
		line   int
		expect int
		desc   string
	}{
		{"foo.go", 11, 2, "first added line in first hunk"},
		{"foo.go", 12, 3, "second added line in first hunk"},
		{"foo.go", 30, 5, "added line in second hunk"},
		{"foo.go", 100, 0, "outside any hunk"},
		{"bar.go", 11, 0, "unknown file"},
	}
	for _, tc := range cases {
		got := github.PositionForLine(d, tc.file, tc.line)
		if got != tc.expect {
			t.Errorf("%s: PositionForLine(%s, %d) = %d, want %d",
				tc.desc, tc.file, tc.line, got, tc.expect)
		}
	}
}
