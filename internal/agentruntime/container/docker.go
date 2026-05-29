package container

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

// DockerRuntime is the production Runtime backed by the Docker SDK.
type DockerRuntime struct {
	cli *client.Client

	// JobSpecDir is the host-side directory where ContainerSpec.JobSpecJSON
	// is materialized before being bind-mounted at /job/spec.json. Defaults
	// to os.TempDir() when empty.
	JobSpecDir string
}

// NewDockerRuntime opens a Docker client via the standard env. Returns an
// error when Docker is not reachable so tests can `t.Skip`.
func NewDockerRuntime() (*DockerRuntime, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	if _, err := cli.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("docker ping: %w", err)
	}
	return &DockerRuntime{cli: cli}, nil
}

// Close releases the Docker client.
func (d *DockerRuntime) Close() error {
	if d.cli == nil {
		return nil
	}
	return d.cli.Close()
}

func (d *DockerRuntime) Create(ctx context.Context, spec ContainerSpec) (string, error) {
	if spec.Image == "" {
		return "", errors.New("container: spec.Image is required")
	}
	// Materialize the job spec to a host file we can bind-mount RO.
	dir := d.JobSpecDir
	if dir == "" {
		dir = os.TempDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir job spec dir: %w", err)
	}
	specFile, err := os.CreateTemp(dir, "quokka-jobspec-*.json")
	if err != nil {
		return "", fmt.Errorf("create job spec: %w", err)
	}
	if _, err := specFile.Write(spec.JobSpecJSON); err != nil {
		_ = specFile.Close()
		return "", err
	}
	_ = specFile.Close()
	hostSpec := specFile.Name()

	env := make([]string, 0, len(spec.Env))
	for k, v := range spec.Env {
		env = append(env, k+"="+v)
	}

	containerCfg := &container.Config{
		Image: spec.Image,
		Env:   env,
		Cmd:   nil, // image ENTRYPOINT runs `quokka agent run --job-file /job/spec.json`
	}

	mounts := []mount.Mount{
		{
			Type:   mount.TypeBind,
			Source: hostSpec,
			Target: "/job/spec.json",
			ReadOnly: true,
		},
	}
	if spec.RepoPath != "" {
		mounts = append(mounts, mount.Mount{
			Type:   mount.TypeBind,
			Source: filepath.Clean(spec.RepoPath),
			Target: "/workspace",
		})
	}
	if spec.StatePath != "" {
		mounts = append(mounts, mount.Mount{
			Type:   mount.TypeBind,
			Source: filepath.Clean(spec.StatePath),
			Target: "/state",
		})
	}
	for _, sm := range spec.SocketBindMounts {
		mounts = append(mounts, mount.Mount{
			Type:   mount.TypeBind,
			Source: filepath.Clean(sm.HostPath),
			Target: sm.ContainerPath,
		})
	}

	res := spec.Resources
	if res.MemoryBytes == 0 && res.NanoCPUs == 0 && res.PidsLimit == 0 {
		res = DefaultResources()
	}
	pidsLimit := res.PidsLimit
	hostCfg := &container.HostConfig{
		ReadonlyRootfs: true,
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges"},
		AutoRemove:     false,
		Mounts:         mounts,
		Resources: container.Resources{
			Memory:    res.MemoryBytes,
			NanoCPUs:  res.NanoCPUs,
			PidsLimit: &pidsLimit,
		},
	}
	if spec.NetworkID != "" {
		hostCfg.NetworkMode = container.NetworkMode(spec.NetworkID)
	}

	resp, err := d.cli.ContainerCreate(ctx, containerCfg, hostCfg, nil, nil, "")
	if err != nil {
		return "", fmt.Errorf("container create: %w", err)
	}
	return resp.ID, nil
}

func (d *DockerRuntime) Start(ctx context.Context, id string) error {
	return d.cli.ContainerStart(ctx, id, container.StartOptions{})
}

func (d *DockerRuntime) StreamLogs(ctx context.Context, id string) (<-chan LogLine, error) {
	rc, err := d.cli.ContainerLogs(ctx, id, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
	})
	if err != nil {
		return nil, fmt.Errorf("container logs: %w", err)
	}
	ch := make(chan LogLine, 64)
	go func() {
		defer close(ch)
		defer rc.Close()
		outR, outW := io.Pipe()
		errR, errW := io.Pipe()
		copyDone := make(chan struct{})
		go func() {
			_, _ = stdcopy.StdCopy(outW, errW, rc)
			_ = outW.Close()
			_ = errW.Close()
			close(copyDone)
		}()
		readLines := func(r io.Reader, stream string) chan struct{} {
			done := make(chan struct{})
			go func() {
				defer close(done)
				sc := bufio.NewScanner(r)
				sc.Buffer(make([]byte, 64*1024), 4<<20)
				for sc.Scan() {
					select {
					case ch <- LogLine{Stream: stream, Text: sc.Text()}:
					case <-ctx.Done():
						return
					}
				}
			}()
			return done
		}
		outDone := readLines(outR, "stdout")
		errDone := readLines(errR, "stderr")
		<-outDone
		<-errDone
		<-copyDone
	}()
	return ch, nil
}

func (d *DockerRuntime) Wait(ctx context.Context, id string) (int, error) {
	statusCh, errCh := d.cli.ContainerWait(ctx, id, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return -1, fmt.Errorf("container wait: %w", err)
		}
		return 0, nil
	case s := <-statusCh:
		return int(s.StatusCode), nil
	case <-ctx.Done():
		return -1, ctx.Err()
	}
}

func (d *DockerRuntime) Kill(ctx context.Context, id string) error {
	if err := d.cli.ContainerKill(ctx, id, "SIGKILL"); err != nil {
		// Idempotent — ignore "no such container".
		if client.IsErrNotFound(err) {
			return nil
		}
		return err
	}
	return nil
}

func (d *DockerRuntime) Remove(ctx context.Context, id string) error {
	err := d.cli.ContainerRemove(ctx, id, container.RemoveOptions{Force: true})
	if err != nil && client.IsErrNotFound(err) {
		return nil
	}
	return err
}
