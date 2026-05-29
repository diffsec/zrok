package llm_test

import (
	"bytes"
	"io"
	"os"
	"sort"
	"testing"

	"github.com/diffsec/quokka/internal/llm"
	"github.com/diffsec/quokka/internal/llm/anthropic"
	"github.com/diffsec/quokka/internal/llm/openai"
)

// TestSSEFixtureParity proves the two adapters parse their respective
// fixture bytes into the same logical Event sequence. Usage/StopReason
// can swap order between adapters; we normalise by separating those out
// and comparing the content event stream (text + tool blocks) verbatim.
func TestSSEFixtureParity(t *testing.T) {
	anthEvents := drainFixture(t, "testdata/anthropic_text_then_tool.sse", anthropic.ParseSSE)
	oaiEvents := drainFixture(t, "testdata/openai_text_then_tool.sse", openai.ParseSSE)

	anthContent, anthMeta := split(anthEvents)
	oaiContent, oaiMeta := split(oaiEvents)

	if !equalEvents(anthContent, oaiContent) {
		t.Fatalf("content event sequence differs:\nanthropic: %#v\nopenai:    %#v", anthContent, oaiContent)
	}
	sortMeta(anthMeta)
	sortMeta(oaiMeta)
	if !equalEvents(anthMeta, oaiMeta) {
		t.Fatalf("meta event set differs:\nanthropic: %#v\nopenai:    %#v", anthMeta, oaiMeta)
	}
}

func drainFixture(t *testing.T, path string, parse func(r io.Reader, ch chan<- llm.Event)) []llm.Event {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan llm.Event, 64)
	parse(bytes.NewReader(raw), ch)
	close(ch)
	var out []llm.Event
	for ev := range ch {
		out = append(out, ev)
	}
	return out
}

func split(evs []llm.Event) (content, meta []llm.Event) {
	for _, e := range evs {
		switch e.Kind {
		case llm.EventUsageDelta, llm.EventStopReason:
			meta = append(meta, e)
		default:
			content = append(content, e)
		}
	}
	return
}

func sortMeta(evs []llm.Event) {
	sort.Slice(evs, func(i, j int) bool {
		return string(evs[i].Kind) < string(evs[j].Kind)
	})
}

func equalEvents(a, b []llm.Event) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
