package container

import (
	"context"
	"errors"
	"strconv"
	"sync"
)

// FakeRuntime is the test-friendly Runtime: it records each Create call,
// fans LogLines for any container it created, and lets the test drive the
// exit code via SetExitCode.
type FakeRuntime struct {
	mu       sync.Mutex
	nextID   int
	specs    map[string]ContainerSpec
	logs     map[string][]LogLine
	exits    map[string]int
	killed   map[string]bool
	removed  map[string]bool
	stopChan map[string]chan struct{}
}

// NewFakeRuntime constructs an empty FakeRuntime.
func NewFakeRuntime() *FakeRuntime {
	return &FakeRuntime{
		specs:    map[string]ContainerSpec{},
		logs:     map[string][]LogLine{},
		exits:    map[string]int{},
		killed:   map[string]bool{},
		removed:  map[string]bool{},
		stopChan: map[string]chan struct{}{},
	}
}

// Create assigns a synthetic ID.
func (f *FakeRuntime) Create(ctx context.Context, spec ContainerSpec) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	id := "fake-" + strconv.Itoa(f.nextID)
	f.specs[id] = spec
	f.stopChan[id] = make(chan struct{})
	return id, nil
}

// Start is a no-op.
func (f *FakeRuntime) Start(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.specs[id]; !ok {
		return errors.New("fake: unknown container " + id)
	}
	return nil
}

// QueueLog appends a log line for the next StreamLogs.
func (f *FakeRuntime) QueueLog(id, stream, text string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logs[id] = append(f.logs[id], LogLine{Stream: stream, Text: text})
}

// SetExitCode lets the test stop a "running" container with code c.
func (f *FakeRuntime) SetExitCode(id string, c int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.exits[id] = c
	if ch, ok := f.stopChan[id]; ok {
		select {
		case <-ch:
		default:
			close(ch)
		}
	}
}

// StreamLogs emits the queued log lines then closes when SetExitCode has been
// called for the container.
func (f *FakeRuntime) StreamLogs(ctx context.Context, id string) (<-chan LogLine, error) {
	f.mu.Lock()
	lines := append([]LogLine(nil), f.logs[id]...)
	stop := f.stopChan[id]
	f.mu.Unlock()
	if stop == nil {
		return nil, errors.New("fake: unknown container " + id)
	}
	out := make(chan LogLine, len(lines)+1)
	go func() {
		defer close(out)
		for _, l := range lines {
			select {
			case out <- l:
			case <-ctx.Done():
				return
			}
		}
		// Wait until the test marks the container exited.
		select {
		case <-stop:
		case <-ctx.Done():
		}
	}()
	return out, nil
}

// Wait returns whatever SetExitCode set, or blocks until ctx is done.
func (f *FakeRuntime) Wait(ctx context.Context, id string) (int, error) {
	f.mu.Lock()
	stop := f.stopChan[id]
	f.mu.Unlock()
	if stop == nil {
		return -1, errors.New("fake: unknown container " + id)
	}
	select {
	case <-stop:
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.exits[id], nil
	case <-ctx.Done():
		return -1, ctx.Err()
	}
}

// Kill marks the container killed and unblocks Wait.
func (f *FakeRuntime) Kill(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.killed[id] = true
	if ch, ok := f.stopChan[id]; ok {
		select {
		case <-ch:
		default:
			f.exits[id] = 137
			close(ch)
		}
	}
	return nil
}

// Remove marks the container removed.
func (f *FakeRuntime) Remove(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed[id] = true
	return nil
}

// LastSpec returns the most recently created ContainerSpec for assertions.
func (f *FakeRuntime) LastSpec() (ContainerSpec, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var last string
	for id := range f.specs {
		if id > last {
			last = id
		}
	}
	if last == "" {
		return ContainerSpec{}, false
	}
	return f.specs[last], true
}

// Killed reports whether Kill was called for id.
func (f *FakeRuntime) Killed(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.killed[id]
}

// Removed reports whether Remove was called for id.
func (f *FakeRuntime) Removed(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.removed[id]
}
