package github

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Hunk is one contiguous range of changed lines on the new side of a PR
// diff. StartLine/Length cover the post-image lines; Position is the offset
// (1-indexed) within the unified diff that GitHub uses for inline review
// comments.
type Hunk struct {
	StartLine int
	Length    int
	Position  int
}

// DiffPosition is the file-to-hunks map ParseUnifiedDiff returns.
type DiffPosition map[string][]Hunk

// ParseUnifiedDiff parses a `git diff --unified=0` stream and returns the
// per-file hunk list. Positions are the GitHub-API "diff position" — the
// 1-based index of each non-header line within the diff, scoped to a file.
//
// This is the unified diff dialect GitHub expects in PR Review comments:
// https://docs.github.com/en/rest/pulls/comments#about-the-position
func ParseUnifiedDiff(r io.Reader) (DiffPosition, error) {
	out := DiffPosition{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	var curFile string
	var pos int
	var inHunk bool
	var hunkNewStart, hunkNewLen int
	var hunkNewIdx int
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "diff --git "):
			curFile = ""
			pos = 0
			inHunk = false
		case strings.HasPrefix(line, "+++ "):
			curFile = strings.TrimPrefix(line, "+++ ")
			curFile = strings.TrimPrefix(curFile, "b/")
			if curFile == "/dev/null" {
				curFile = ""
			}
			pos = 0
		case strings.HasPrefix(line, "@@"):
			// @@ -old,oldlen +new,newlen @@ context
			newRange, ok := parseHunkHeader(line)
			if !ok || curFile == "" {
				continue
			}
			pos++ // The hunk header itself counts as one position.
			hunkNewStart = newRange.start
			hunkNewLen = newRange.length
			hunkNewIdx = 0
			inHunk = true
			out[curFile] = append(out[curFile], Hunk{
				StartLine: hunkNewStart,
				Length:    hunkNewLen,
				Position:  pos,
			})
		default:
			if !inHunk || curFile == "" {
				continue
			}
			pos++
			// In unified=0 diffs, every non-header line is one of:
			//   '+' added (post-image)
			//   '-' removed (pre-image)
			//   ' ' context (rare in --unified=0)
			if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
				// position of this specific new line:
				newLine := hunkNewStart + hunkNewIdx
				hunks := out[curFile]
				if len(hunks) > 0 {
					// We don't store per-line — the hunk's StartLine + offset
					// is what callers compute. Position of this exact line is
					// captured by lineToPosition lookup below.
					hunks[len(hunks)-1].Length = max(hunks[len(hunks)-1].Length, hunkNewIdx+1)
					out[curFile] = hunks
				}
				_ = newLine
				hunkNewIdx++
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// PositionForLine returns the GitHub diff position for a (file, lineStart)
// pair, or 0 when the line is not inside any hunk.
//
// GitHub measures position as the 1-based offset of the line within the diff
// file, counting the hunk header. Because we parsed unified=0 we know that
// each '+' line in a hunk maps deterministically to (header_position + 1 +
// offset_within_hunk).
func PositionForLine(d DiffPosition, file string, line int) int {
	hunks, ok := d[file]
	if !ok {
		return 0
	}
	for _, h := range hunks {
		if line >= h.StartLine && line < h.StartLine+max(h.Length, 1) {
			return h.Position + (line - h.StartLine) + 1
		}
	}
	return 0
}

type rng struct{ start, length int }

func parseHunkHeader(line string) (rng, bool) {
	// @@ -a,b +c,d @@
	i := strings.Index(line, "+")
	if i < 0 {
		return rng{}, false
	}
	rest := line[i+1:]
	end := strings.Index(rest, " ")
	if end < 0 {
		return rng{}, false
	}
	spec := rest[:end]
	parts := strings.SplitN(spec, ",", 2)
	start, err := strconv.Atoi(parts[0])
	if err != nil {
		return rng{}, false
	}
	length := 1
	if len(parts) == 2 {
		l, err := strconv.Atoi(parts[1])
		if err != nil {
			return rng{}, false
		}
		length = l
	}
	return rng{start: start, length: length}, true
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// String is a tiny helper for debug logging.
func (h Hunk) String() string {
	return fmt.Sprintf("@@+%d,%d pos=%d", h.StartLine, h.Length, h.Position)
}
