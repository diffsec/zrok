package transcript

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/diffsec/quokka/internal/agentloop"
	"github.com/diffsec/quokka/internal/store"
)

// timelineKinds are the EventKinds the DBSink also materializes as
// timeline_events rows. Everything else stays in the transcript log.
var timelineKinds = map[agentloop.EventKind]bool{
	agentloop.KindAgentStart:          true,
	agentloop.KindAgentEnd:            true,
	agentloop.KindToolCall:            true,
	agentloop.KindUsage:               true,
	agentloop.KindError:               true,
	agentloop.KindLoopAbortedMaxIters: true,
	agentloop.KindBudgetExceeded:      true,
}

// DBSink is an EventSink that:
//   - buffers events to a per-agent NDJSON file under <dataRoot>/runs/<run>/<agent>.log
//   - on Close, hashes + registers the file via TranscriptStore.Put
//   - emits a timeline_events row for the subset of EventKinds in timelineKinds
//
// One DBSink per (run, agent) invocation. The worker constructs one before
// it spawns the agent and Closes it after the agent terminates.
type DBSink struct {
	RunID        string
	AgentName    string
	InvocationID string
	DataRoot     string

	Stores *store.Stores

	mu     sync.Mutex
	file   *os.File
	hasher interface {
		io.Writer
		Sum(b []byte) []byte
	}
	bytes int64
	err   error
}

// NewDBSink opens the per-agent log file and returns a ready-to-use DBSink.
// Returns an error if the file can't be created.
func NewDBSink(runID, agentName, invocationID, dataRoot string, stores *store.Stores) (*DBSink, error) {
	dir := filepath.Join(dataRoot, "runs", runID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("transcript: mkdir %s: %w", dir, err)
	}
	path := filepath.Join(dir, agentName+".log")
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("transcript: create %s: %w", path, err)
	}
	return &DBSink{
		RunID:        runID,
		AgentName:    agentName,
		InvocationID: invocationID,
		DataRoot:     dataRoot,
		Stores:       stores,
		file:         f,
		hasher:       sha256.New(),
	}, nil
}

// Emit writes one NDJSON line and, for selected kinds, appends a timeline
// event. Errors are recorded on the sink and surfaced from Close.
func (s *DBSink) Emit(ev agentloop.TranscriptEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil || s.file == nil {
		return
	}
	line, err := json.Marshal(eventWire{
		RunID:     ev.RunID,
		AgentName: ev.AgentName,
		Seq:       ev.Seq,
		Timestamp: ev.Timestamp.Format("2006-01-02T15:04:05.000000000Z07:00"),
		Kind:      string(ev.Kind),
		Payload:   ev.Payload,
	})
	if err != nil {
		s.err = err
		return
	}
	line = append(line, '\n')
	n, werr := s.file.Write(line)
	if werr != nil {
		s.err = werr
		return
	}
	s.bytes += int64(n)
	_, _ = s.hasher.Write(line)

	if s.Stores != nil && s.Stores.Events != nil && timelineKinds[ev.Kind] {
		payload := map[string]any{
			"agent":   ev.AgentName,
			"seq":     ev.Seq,
			"kind":    string(ev.Kind),
			"payload": ev.Payload,
		}
		js, _ := json.Marshal(payload)
		_ = s.Stores.Events.Append(context.Background(), ev.RunID, string(ev.Kind), string(js))
	}
}

// Close flushes the file, registers it with TranscriptStore.Put, and returns
// the storage URI plus any deferred error.
func (s *DBSink) Close(ctx context.Context) (storageURI string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return "", s.err
	}
	path := s.file.Name()
	if err := s.file.Close(); err != nil && s.err == nil {
		s.err = err
	}
	s.file = nil
	if s.err != nil {
		return "", s.err
	}
	uri := "file://" + path
	sum := hex.EncodeToString(s.hasher.Sum(nil))
	if s.Stores != nil && s.Stores.Transcripts != nil {
		if err := s.Stores.Transcripts.Put(ctx, s.RunID, s.InvocationID, s.AgentName, uri, sum, s.bytes); err != nil {
			return uri, err
		}
	}
	return uri, nil
}

// eventWire is the on-disk shape we serialize per line. Keeping a flat struct
// (vs. raw agentloop.TranscriptEvent) keeps the format stable across refactors.
type eventWire struct {
	RunID     string `json:"run_id"`
	AgentName string `json:"agent_name"`
	Seq       int    `json:"seq"`
	Timestamp string `json:"ts"`
	Kind      string `json:"kind"`
	Payload   any    `json:"payload,omitempty"`
}
