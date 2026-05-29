// Package container is the Docker-SDK-backed runtime that spawns one container
// per agent invocation. Mounts, security defaults, and resource limits are
// codified in ContainerSpec; the Runtime interface lets the worker substitute
// a fake in tests.
package container

import "time"

// ContainerSpec is the input to Runtime.Create.
type ContainerSpec struct {
	// Image is the runner image tag.
	Image string
	// JobSpecJSON is the bytes that get written into /job/spec.json inside
	// the container.
	JobSpecJSON []byte
	// RepoPath is the host-side path of the cloned working tree that gets
	// bind-mounted at /workspace.
	RepoPath string
	// StatePath is the host-side path of the per-repo persistent volume
	// that gets bind-mounted at /state (vector index + file_hashes).
	StatePath string
	// Env is the environment variables to inject (PROVIDER_API_KEY, etc).
	Env map[string]string
	// SocketBindMounts is the list of host-side socket files to bind-mount
	// read-write into the container. The runner uses this to expose the
	// per-run RPC socket at /var/run/quokka.sock.
	SocketBindMounts []SocketMount
	// Resources caps memory/cpu/pids.
	Resources Resources
	// NetworkID is the Docker network to attach. Empty = bridge.
	NetworkID string
	// Timeout is the maximum wall-clock duration. Caller's context typically
	// enforces this; the runtime additionally SIGKILLs after Timeout+grace.
	Timeout time.Duration
}

// Resources is the per-container resource cap.
type Resources struct {
	// MemoryBytes is the hard memory limit.
	MemoryBytes int64
	// NanoCPUs is the CPU cap in 10^-9 cores. 2_000_000_000 = 2 CPUs.
	NanoCPUs int64
	// PidsLimit caps the process count.
	PidsLimit int64
}

// DefaultResources is the v1 cap: 4 GiB / 2 CPUs / 512 pids.
func DefaultResources() Resources {
	return Resources{
		MemoryBytes: 4 << 30,
		NanoCPUs:    2_000_000_000,
		PidsLimit:   512,
	}
}

// SocketMount is one host→container Unix socket bind. The host path
// must already exist when Create is called.
type SocketMount struct {
	HostPath      string
	ContainerPath string
}

// LogLine is one demuxed line from container stdout/stderr.
type LogLine struct {
	Stream string // "stdout" or "stderr"
	Text   string
}
