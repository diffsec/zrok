package transcript_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/diffsec/quokka/internal/agentloop"
	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/transcript"
)

type fakeTranscriptStore struct {
	put []store.Transcript
}

func (f *fakeTranscriptStore) Put(ctx context.Context, runID, invID, agent, uri, sha string, bytes int64) error {
	f.put = append(f.put, store.Transcript{
		RunID:        runID,
		InvocationID: invID,
		AgentName:    agent,
		StorageURI:   uri,
		SHA256:       sha,
		ByteSize:     bytes,
	})
	return nil
}
func (f *fakeTranscriptStore) List(ctx context.Context, runID string) ([]*store.Transcript, error) {
	return nil, nil
}
func (f *fakeTranscriptStore) Get(ctx context.Context, id string) (*store.Transcript, error) {
	return nil, store.ErrNotFound
}

type fakeEventStore struct {
	events []store.TimelineEvent
}

func (f *fakeEventStore) Append(ctx context.Context, runID, eventType, payloadJSON string) error {
	f.events = append(f.events, store.TimelineEvent{
		RunID:       runID,
		EventType:   eventType,
		PayloadJSON: payloadJSON,
	})
	return nil
}
func (f *fakeEventStore) Stream(ctx context.Context, runID string, since time.Time) ([]*store.TimelineEvent, error) {
	return nil, nil
}

func TestDBSinkWritesLogAndRegistersTranscript(t *testing.T) {
	dir := t.TempDir()
	ts := &fakeTranscriptStore{}
	es := &fakeEventStore{}
	stores := &store.Stores{Transcripts: ts, Events: es}

	sink, err := transcript.NewDBSink("run-1", "security-agent", "inv-1", dir, stores)
	if err != nil {
		t.Fatalf("NewDBSink: %v", err)
	}

	sink.Emit(agentloop.TranscriptEvent{
		RunID:     "run-1",
		AgentName: "security-agent",
		Seq:       1,
		Timestamp: time.Now(),
		Kind:      agentloop.KindAgentStart,
		Payload:   map[string]string{"agent": "security-agent"},
	})
	sink.Emit(agentloop.TranscriptEvent{
		RunID:     "run-1",
		AgentName: "security-agent",
		Seq:       2,
		Timestamp: time.Now(),
		Kind:      agentloop.KindAssistantText,
		Payload:   "hello",
	})

	uri, err := sink.Close(context.Background())
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !strings.HasPrefix(uri, "file://") {
		t.Fatalf("expected file:// URI, got %q", uri)
	}
	path := filepath.Join(dir, "runs", "run-1", "security-agent.log")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 NDJSON lines, got %d: %q", len(lines), string(b))
	}

	if len(ts.put) != 1 {
		t.Fatalf("expected one Transcripts.Put, got %d", len(ts.put))
	}
	if ts.put[0].SHA256 == "" {
		t.Fatalf("expected non-empty SHA256")
	}
	// Only the agent_start kind is on the timelineKinds list (assistant_text isn't).
	if len(es.events) != 1 {
		t.Fatalf("expected one timeline event, got %d", len(es.events))
	}
	if es.events[0].EventType != string(agentloop.KindAgentStart) {
		t.Fatalf("expected agent_start, got %s", es.events[0].EventType)
	}
}

func TestBroadcasterDropsUnderBackpressure(t *testing.T) {
	b := transcript.NewBroadcaster()
	ch, unsub := b.Subscribe("run-x", 1)
	defer unsub()

	// First publish fills the buffer.
	b.Publish(agentloop.TranscriptEvent{RunID: "run-x", Seq: 1})
	// Second should drop without blocking.
	done := make(chan struct{})
	go func() {
		b.Publish(agentloop.TranscriptEvent{RunID: "run-x", Seq: 2})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Publish blocked under back-pressure")
	}
	// Drain the one event we expect.
	select {
	case ev := <-ch:
		if ev.Seq != 1 {
			t.Fatalf("expected seq=1, got %d", ev.Seq)
		}
	case <-time.After(time.Second):
		t.Fatal("no event received")
	}
}

func TestBroadcasterSubscribeUnsubscribe(t *testing.T) {
	b := transcript.NewBroadcaster()
	ch, unsub := b.Subscribe("r", 8)
	b.Publish(agentloop.TranscriptEvent{RunID: "r", Seq: 7})
	select {
	case ev := <-ch:
		if ev.Seq != 7 {
			t.Fatalf("expected 7, got %d", ev.Seq)
		}
	case <-time.After(time.Second):
		t.Fatal("no delivery")
	}
	unsub()
	// After unsub, publish is a no-op for this subscriber and the channel is closed.
	b.Publish(agentloop.TranscriptEvent{RunID: "r", Seq: 8})
	if _, ok := <-ch; ok {
		t.Fatal("expected closed channel after Unsubscribe")
	}
}
