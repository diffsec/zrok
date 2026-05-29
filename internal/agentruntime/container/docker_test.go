package container_test

import (
	"context"
	"testing"
	"time"

	"github.com/diffsec/quokka/internal/agentruntime/container"
)

func TestDockerLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("docker lifecycle test is integration-only; -short skips")
	}
	rt, err := container.NewDockerRuntime()
	if err != nil {
		t.Skipf("docker unavailable: %v", err)
	}
	defer func() { _ = rt.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	id, err := rt.Create(ctx, container.ContainerSpec{
		Image: "busybox:latest",
		Env: map[string]string{
			"MSG": "hello",
		},
		Resources: container.DefaultResources(),
	})
	if err != nil {
		t.Skipf("create busybox: %v (image may not be cached)", err)
	}
	t.Cleanup(func() { _ = rt.Remove(context.Background(), id) })

	if err := rt.Start(ctx, id); err != nil {
		t.Fatalf("start: %v", err)
	}
	logs, err := rt.StreamLogs(ctx, id)
	if err != nil {
		t.Fatalf("logs: %v", err)
	}
	_, err = rt.Wait(ctx, id)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	// Drain logs (busybox with no command exits immediately).
	for range logs {
	}
}
