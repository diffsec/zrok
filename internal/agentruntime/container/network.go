package container

// EgressPolicy describes the allowed network surface for a run. v1 ships a
// single mode: allowlist-providers, implemented as a Docker network with no
// internet access plus an env-var pointing at a host-side HTTP CONNECT
// proxy that allowlists provider hosts.
//
// The proxy itself is out of scope for PR-4; this file documents the wire
// format and the env vars the runner image reads on startup.
//
// EnvProxyURL: HTTPS_PROXY / HTTP_PROXY pointed at the proxy listener.
// EnvAllowedHosts: comma-separated list, surfaced for diagnostics.
type EgressPolicy struct {
	Mode            string
	EnvProxyURL     string
	EnvAllowedHosts string
}

// AllowlistProviders is the v1 default.
func AllowlistProviders(proxyURL string, allowedHosts []string) EgressPolicy {
	hosts := ""
	for i, h := range allowedHosts {
		if i > 0 {
			hosts += ","
		}
		hosts += h
	}
	return EgressPolicy{
		Mode:            "allowlist-providers",
		EnvProxyURL:     proxyURL,
		EnvAllowedHosts: hosts,
	}
}
