package jobs

import (
	"testing"
)

// TestContainerSpecFromJobSpec_EnvInjection asserts that the worker
// injects QUOKKA_PROVIDER_<LABEL>_* env vars on the ContainerSpec
// (the sidecar reads them through NewEnvProviderFactory).
func TestContainerSpecFromJobSpec_EnvInjection(t *testing.T) {
	deps := &Deps{
		DataRoot:    "/tmp",
		RunnerImage: "img:test",
	}
	spec := JobSpec{
		SpecVersion: 1,
		RunID:       "run-1",
		RepoID:      "repo-1",
		OrgID:       "org-1",
		RPCSocket:   "/var/run/quokka.sock",
		RPCToken:    "tok-123",
	}
	prov := ProviderResolution{
		Label:    "default",
		Protocol: "anthropic",
		BaseURL:  "https://api.anthropic.com",
		APIKey:   "sk-secret",
	}
	cs, err := containerSpecFromJobSpec(deps, spec, prov, "/repo", "/tmp/qkrun-xxxxxx/s")
	if err != nil {
		t.Fatalf("containerSpecFromJobSpec: %v", err)
	}
	if cs.Env["QUOKKA_RUN_ID"] != "run-1" {
		t.Errorf("missing QUOKKA_RUN_ID: %v", cs.Env)
	}
	if cs.Env["QUOKKA_RPC_TOKEN"] != "tok-123" {
		t.Errorf("missing QUOKKA_RPC_TOKEN: %v", cs.Env)
	}
	if cs.Env["QUOKKA_RPC_SOCKET"] != "/var/run/quokka.sock" {
		t.Errorf("missing QUOKKA_RPC_SOCKET: %v", cs.Env)
	}
	if cs.Env["QUOKKA_PROVIDER_DEFAULT_KEY"] != "sk-secret" {
		t.Errorf("missing QUOKKA_PROVIDER_DEFAULT_KEY: %v", cs.Env)
	}
	if cs.Env["QUOKKA_PROVIDER_DEFAULT_PROTOCOL"] != "anthropic" {
		t.Errorf("missing QUOKKA_PROVIDER_DEFAULT_PROTOCOL: %v", cs.Env)
	}
	if cs.Env["QUOKKA_PROVIDER_DEFAULT_BASE_URL"] != "https://api.anthropic.com" {
		t.Errorf("missing QUOKKA_PROVIDER_DEFAULT_BASE_URL: %v", cs.Env)
	}
	if len(cs.SocketBindMounts) != 1 || cs.SocketBindMounts[0].ContainerPath != "/var/run/quokka.sock" {
		t.Errorf("expected single socket mount at /var/run/quokka.sock; got %+v", cs.SocketBindMounts)
	}
	if cs.RepoPath != "/repo" {
		t.Errorf("expected RepoPath=/repo, got %q", cs.RepoPath)
	}
}
