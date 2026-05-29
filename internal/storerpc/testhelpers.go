package storerpc

import (
	"context"
	"encoding/json"
	"net"
)

// ServeConnForTest drives a single net.Conn through the server's
// dispatch loop. Used by tests that pair the server with net.Pipe so
// they don't need a Unix socket on disk.
func (s *Server) ServeConnForTest(c net.Conn) {
	s.wg.Add(1)
	s.serveConn(c)
}

// CallRawForTest issues an arbitrary method call with a JSON request
// body. Used by tests that need to probe the allowlist (e.g. sending
// "Providers.Get" should be rejected).
func (c *Client) CallRawForTest(ctx context.Context, method string, req json.RawMessage, out any) error {
	return c.call(ctx, method, json.RawMessage(req), out)
}
