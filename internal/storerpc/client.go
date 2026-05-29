package storerpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/diffsec/quokka/internal/store"
)

// Client is the sidecar-side handle to a Server. The wire is one
// long-lived connection guarded by a write mutex; each call serializes
// behind it. Concurrent callers serialize at the mutex.
type Client struct {
	token string

	mu    sync.Mutex
	conn  net.Conn
	br    *bufio.Reader
	close func() error
}

// Dial opens a Unix socket connection and returns a Client. Caller
// supplies token (same secret the host set via Server.Authenticate).
func Dial(socketPath, token string) (*Client, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("storerpc: dial %s: %w", socketPath, err)
	}
	return NewClient(conn, token), nil
}

// NewClient wraps an existing net.Conn (used by tests with net.Pipe).
func NewClient(conn net.Conn, token string) *Client {
	return &Client{
		token: token,
		conn:  conn,
		br:    bufio.NewReader(conn),
		close: conn.Close,
	}
}

// Close shuts down the connection.
func (c *Client) Close() error {
	if c == nil || c.close == nil {
		return nil
	}
	return c.close()
}

// call serializes one round-trip. Marshals req as JSON, sends the
// envelope, reads one reply, decodes res into out (if non-nil).
func (c *Client) call(_ context.Context, method string, req, out any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("storerpc: encode req for %s: %w", method, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := writeEnvelope(c.conn, Envelope{
		Token:   c.token,
		Method:  method,
		Request: body,
	}); err != nil {
		return err
	}
	rep, err := readReply(c.br)
	if err != nil {
		return err
	}
	if rep.Error != "" {
		return rpcClientError(rep)
	}
	if out != nil && len(rep.Result) > 0 {
		if err := json.Unmarshal(rep.Result, out); err != nil {
			return fmt.Errorf("storerpc: decode %s result: %w", method, err)
		}
	}
	return nil
}

// rpcClientError builds a typed error from a Reply. ErrNotFound is
// surfaced so callers using errors.Is(err, store.ErrNotFound) work
// across the RPC boundary.
func rpcClientError(rep Reply) error {
	switch rep.ErrorCode {
	case CodeNotFound:
		return fmt.Errorf("%w: %s", store.ErrNotFound, rep.Error)
	default:
		return errors.New(rep.Error)
	}
}

// --- FindingStore implementation ---

// FindingClient implements store.FindingStore over the RPC.
type FindingClient struct{ c *Client }

// Findings returns a store.FindingStore client bound to c.
func (c *Client) Findings() *FindingClient { return &FindingClient{c: c} }

func (f *FindingClient) Create(ctx context.Context, row *store.FindingRow) error {
	var res FindingsCreateRes
	if err := f.c.call(ctx, MethodFindingsCreate, FindingsCreateReq{Row: *row}, &res); err != nil {
		return err
	}
	*row = res.Row
	return nil
}

func (f *FindingClient) Get(ctx context.Context, id string) (*store.FindingRow, error) {
	var res FindingsGetRes
	if err := f.c.call(ctx, MethodFindingsGet, FindingsGetReq{ID: id}, &res); err != nil {
		return nil, err
	}
	row := res.Row
	return &row, nil
}

func (f *FindingClient) FindByFingerprintAndCreator(ctx context.Context, repoID, fingerprint, createdBy string) (*store.FindingRow, error) {
	var res FindingsGetRes
	if err := f.c.call(ctx, MethodFindingsFindByFingerprint, FindingsFindByFingerprintReq{
		RepoID:      repoID,
		Fingerprint: fingerprint,
		CreatedBy:   createdBy,
	}, &res); err != nil {
		return nil, err
	}
	row := res.Row
	return &row, nil
}

func (f *FindingClient) List(ctx context.Context, repoID string) ([]*store.FindingRow, error) {
	var res FindingsListRes
	if err := f.c.call(ctx, MethodFindingsList, FindingsListReq{RepoID: repoID}, &res); err != nil {
		return nil, err
	}
	out := make([]*store.FindingRow, len(res.Rows))
	for i := range res.Rows {
		r := res.Rows[i]
		out[i] = &r
	}
	return out, nil
}

func (f *FindingClient) ListByRun(ctx context.Context, runID string) ([]*store.FindingRow, error) {
	var res FindingsListRes
	if err := f.c.call(ctx, MethodFindingsListByRun, FindingsListByRunReq{RunID: runID}, &res); err != nil {
		return nil, err
	}
	out := make([]*store.FindingRow, len(res.Rows))
	for i := range res.Rows {
		r := res.Rows[i]
		out[i] = &r
	}
	return out, nil
}

func (f *FindingClient) Update(ctx context.Context, row *store.FindingRow) error {
	return f.c.call(ctx, MethodFindingsUpdate, FindingsUpdateReq{Row: *row}, &EmptyRes{})
}

func (f *FindingClient) UpdateStatus(ctx context.Context, id, status string) error {
	return f.c.call(ctx, MethodFindingsUpdateStatus, FindingsUpdateStatusReq{ID: id, Status: status}, &EmptyRes{})
}

func (f *FindingClient) Delete(ctx context.Context, id string) error {
	// Not exposed over RPC — sidecar should not delete findings.
	return errors.New("storerpc: Findings.Delete is not exposed to the sidecar")
}

func (f *FindingClient) AutoResolveMissing(ctx context.Context, repoID string, seenFingerprints []string) (int64, error) {
	var res FindingsAutoResolveMissingRes
	if err := f.c.call(ctx, MethodFindingsAutoResolveMissing, FindingsAutoResolveMissingReq{
		RepoID:           repoID,
		SeenFingerprints: seenFingerprints,
	}, &res); err != nil {
		return 0, err
	}
	return res.Count, nil
}

// Compile-time assertion.
var _ store.FindingStore = (*FindingClient)(nil)

// --- MemoryStore implementation ---

// MemoryClient implements store.MemoryStore over the RPC.
type MemoryClient struct{ c *Client }

// Memories returns a store.MemoryStore client bound to c.
func (c *Client) Memories() *MemoryClient { return &MemoryClient{c: c} }

func (m *MemoryClient) Upsert(ctx context.Context, row *store.MemoryRow) error {
	var res MemoriesUpsertRes
	if err := m.c.call(ctx, MethodMemoriesUpsert, MemoriesUpsertReq{Row: *row}, &res); err != nil {
		return err
	}
	*row = res.Row
	return nil
}

func (m *MemoryClient) Get(ctx context.Context, repoID, name string) (*store.MemoryRow, error) {
	var res MemoriesGetRes
	if err := m.c.call(ctx, MethodMemoriesGet, MemoriesGetReq{RepoID: repoID, Name: name}, &res); err != nil {
		return nil, err
	}
	row := res.Row
	return &row, nil
}

func (m *MemoryClient) List(ctx context.Context, repoID, memType string) ([]*store.MemoryRow, error) {
	var res MemoriesListRes
	if err := m.c.call(ctx, MethodMemoriesList, MemoriesListReq{RepoID: repoID, Type: memType}, &res); err != nil {
		return nil, err
	}
	out := make([]*store.MemoryRow, len(res.Rows))
	for i := range res.Rows {
		r := res.Rows[i]
		out[i] = &r
	}
	return out, nil
}

func (m *MemoryClient) Delete(ctx context.Context, repoID, name string) error {
	return m.c.call(ctx, MethodMemoriesDelete, MemoriesDeleteReq{RepoID: repoID, Name: name}, &EmptyRes{})
}

func (m *MemoryClient) Search(ctx context.Context, repoID, query string) ([]*store.MemoryRow, error) {
	var res MemoriesListRes
	if err := m.c.call(ctx, MethodMemoriesSearch, MemoriesSearchReq{RepoID: repoID, Query: query}, &res); err != nil {
		return nil, err
	}
	out := make([]*store.MemoryRow, len(res.Rows))
	for i := range res.Rows {
		r := res.Rows[i]
		out[i] = &r
	}
	return out, nil
}

// Compile-time assertion.
var _ store.MemoryStore = (*MemoryClient)(nil)

// --- ExceptionStore implementation ---

// ExceptionClient implements store.ExceptionStore over the RPC.
type ExceptionClient struct{ c *Client }

// Exceptions returns a store.ExceptionStore client bound to c.
func (c *Client) Exceptions() *ExceptionClient { return &ExceptionClient{c: c} }

func (e *ExceptionClient) Create(ctx context.Context, row *store.ExceptionRow) error {
	var res ExceptionsCreateRes
	if err := e.c.call(ctx, MethodExceptionsCreate, ExceptionsCreateReq{Row: *row}, &res); err != nil {
		return err
	}
	*row = res.Row
	return nil
}

func (e *ExceptionClient) Get(ctx context.Context, id string) (*store.ExceptionRow, error) {
	var res ExceptionsGetRes
	if err := e.c.call(ctx, MethodExceptionsGet, ExceptionsGetReq{ID: id}, &res); err != nil {
		return nil, err
	}
	row := res.Row
	return &row, nil
}

func (e *ExceptionClient) List(ctx context.Context, repoID string) ([]*store.ExceptionRow, error) {
	var res ExceptionsListRes
	if err := e.c.call(ctx, MethodExceptionsList, ExceptionsListReq{RepoID: repoID}, &res); err != nil {
		return nil, err
	}
	out := make([]*store.ExceptionRow, len(res.Rows))
	for i := range res.Rows {
		r := res.Rows[i]
		out[i] = &r
	}
	return out, nil
}

func (e *ExceptionClient) Delete(ctx context.Context, id string) error {
	return e.c.call(ctx, MethodExceptionsDelete, ExceptionsDeleteReq{ID: id}, &EmptyRes{})
}

func (e *ExceptionClient) Match(ctx context.Context, repoID, fingerprint, file, cwe, agentName string) (*store.ExceptionRow, error) {
	var res ExceptionsMatchRes
	if err := e.c.call(ctx, MethodExceptionsMatch, ExceptionsMatchReq{
		RepoID:      repoID,
		Fingerprint: fingerprint,
		File:        file,
		CWE:         cwe,
		AgentName:   agentName,
	}, &res); err != nil {
		return nil, err
	}
	return res.Row, nil
}

// Compile-time assertion.
var _ store.ExceptionStore = (*ExceptionClient)(nil)
