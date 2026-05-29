package container

import "context"

// Runtime is the narrow surface the worker uses to spawn and observe a
// container. The Docker impl lives in docker.go; a fake lives in fake.go for
// tests that don't want Docker.
type Runtime interface {
	// Create constructs a container ready to be started. The returned ID
	// is opaque to the caller.
	Create(ctx context.Context, spec ContainerSpec) (id string, err error)
	// Start kicks off the container.
	Start(ctx context.Context, id string) error
	// StreamLogs returns a channel that emits one LogLine per line of
	// container stdout/stderr until the container exits. The channel is
	// closed by the runtime when there is no more output.
	StreamLogs(ctx context.Context, id string) (<-chan LogLine, error)
	// Wait blocks until the container exits and returns its exit code.
	Wait(ctx context.Context, id string) (exitCode int, err error)
	// Kill sends SIGKILL.
	Kill(ctx context.Context, id string) error
	// Remove deletes the container. Idempotent.
	Remove(ctx context.Context, id string) error
}
