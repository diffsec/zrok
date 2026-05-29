package storerpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/diffsec/quokka/internal/store"
)

// Server hosts the RPC over an arbitrary net.Listener. The worker
// constructs one per run, bound to that run's (token, run_id, org_id,
// repo_id) tuple, and Closes it when the run terminates.
//
// Concurrency model: one Accept loop, one goroutine per connection.
// Each connection is sequential (Server reads one Envelope, dispatches,
// writes one Reply, repeats). Parallel agents in the sidecar open
// separate connections.
type Server struct {
	Stores *store.Stores
	Log    *slog.Logger

	// Auth bundle — set via Authenticate before Serve.
	mu      sync.RWMutex
	token   string
	runID   string
	orgID   string
	repoID  string

	listener net.Listener
	wg       sync.WaitGroup
	closed   chan struct{}
}

// NewServer constructs a server bound to s. Call Authenticate, then
// Serve.
func NewServer(s *store.Stores, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		Stores: s,
		Log:    log,
		closed: make(chan struct{}),
	}
}

// Authenticate binds the server to the run's auth scope. Subsequent
// calls must present token; their repo_id arguments must match repoID.
func (s *Server) Authenticate(token, runID, orgID, repoID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = token
	s.runID = runID
	s.orgID = orgID
	s.repoID = repoID
}

// Serve accepts connections on l until Close. Blocks the caller.
func (s *Server) Serve(l net.Listener) error {
	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("storerpc: accept: %w", err)
		}
		s.wg.Add(1)
		go s.serveConn(conn)
	}
}

// Close stops accepting and waits for inflight connections.
func (s *Server) Close() error {
	select {
	case <-s.closed:
		return nil
	default:
		close(s.closed)
	}
	s.mu.RLock()
	l := s.listener
	s.mu.RUnlock()
	var err error
	if l != nil {
		err = l.Close()
	}
	s.wg.Wait()
	return err
}

// serveConn handles one connection's lifecycle: read envelope →
// authenticate → dispatch → write reply, until EOF or error.
func (s *Server) serveConn(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		env, err := readEnvelope(br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			s.Log.Warn("storerpc: read envelope failed", "err", err)
			return
		}
		rep := s.dispatch(context.Background(), env)
		if err := writeReply(conn, rep); err != nil {
			s.Log.Warn("storerpc: write reply failed", "err", err)
			return
		}
	}
}

// dispatch authenticates the call, looks up the method, runs it.
func (s *Server) dispatch(ctx context.Context, env Envelope) Reply {
	s.mu.RLock()
	token := s.token
	expectedRepo := s.repoID
	s.mu.RUnlock()

	if token == "" {
		return errReply(CodeUnauthorized, "server not authenticated")
	}
	if env.Token != token {
		return errReply(CodeUnauthorized, "invalid token")
	}
	if !AllowedMethods[env.Method] {
		return errReply(CodeMethodNotFound, "method not allowed: "+env.Method)
	}
	if s.Stores == nil {
		return errReply(CodeInternal, "server stores not configured")
	}

	switch env.Method {
	case MethodFindingsCreate:
		return s.findingsCreate(ctx, env, expectedRepo)
	case MethodFindingsGet:
		return s.findingsGet(ctx, env, expectedRepo)
	case MethodFindingsList:
		return s.findingsList(ctx, env, expectedRepo)
	case MethodFindingsListByRun:
		return s.findingsListByRun(ctx, env, expectedRepo)
	case MethodFindingsFindByFingerprint:
		return s.findingsFindByFingerprint(ctx, env, expectedRepo)
	case MethodFindingsUpdate:
		return s.findingsUpdate(ctx, env, expectedRepo)
	case MethodFindingsUpdateStatus:
		return s.findingsUpdateStatus(ctx, env, expectedRepo)
	case MethodFindingsAutoResolveMissing:
		return s.findingsAutoResolveMissing(ctx, env, expectedRepo)

	case MethodMemoriesUpsert:
		return s.memoriesUpsert(ctx, env, expectedRepo)
	case MethodMemoriesGet:
		return s.memoriesGet(ctx, env, expectedRepo)
	case MethodMemoriesList:
		return s.memoriesList(ctx, env, expectedRepo)
	case MethodMemoriesDelete:
		return s.memoriesDelete(ctx, env, expectedRepo)
	case MethodMemoriesSearch:
		return s.memoriesSearch(ctx, env, expectedRepo)

	case MethodExceptionsCreate:
		return s.exceptionsCreate(ctx, env, expectedRepo)
	case MethodExceptionsGet:
		return s.exceptionsGet(ctx, env, expectedRepo)
	case MethodExceptionsList:
		return s.exceptionsList(ctx, env, expectedRepo)
	case MethodExceptionsDelete:
		return s.exceptionsDelete(ctx, env, expectedRepo)
	case MethodExceptionsMatch:
		return s.exceptionsMatch(ctx, env, expectedRepo)
	}
	return errReply(CodeMethodNotFound, "unhandled method: "+env.Method)
}

// --- finding handlers ---

func (s *Server) findingsCreate(ctx context.Context, env Envelope, expectedRepo string) Reply {
	var req FindingsCreateReq
	if err := json.Unmarshal(env.Request, &req); err != nil {
		return errReply(CodeBadRequest, err.Error())
	}
	if !scopeOK(req.Row.RepoID, expectedRepo) {
		return errReply(CodeUnauthorized, "repo_id scope mismatch")
	}
	if err := s.Stores.Findings.Create(ctx, &req.Row); err != nil {
		return rpcError(err)
	}
	return okReply(FindingsCreateRes{Row: req.Row})
}

func (s *Server) findingsGet(ctx context.Context, env Envelope, expectedRepo string) Reply {
	var req FindingsGetReq
	if err := json.Unmarshal(env.Request, &req); err != nil {
		return errReply(CodeBadRequest, err.Error())
	}
	row, err := s.Stores.Findings.Get(ctx, req.ID)
	if err != nil {
		return rpcError(err)
	}
	if !scopeOK(row.RepoID, expectedRepo) {
		return errReply(CodeUnauthorized, "repo_id scope mismatch")
	}
	return okReply(FindingsGetRes{Row: *row})
}

func (s *Server) findingsList(ctx context.Context, env Envelope, expectedRepo string) Reply {
	var req FindingsListReq
	if err := json.Unmarshal(env.Request, &req); err != nil {
		return errReply(CodeBadRequest, err.Error())
	}
	if !scopeOK(req.RepoID, expectedRepo) {
		return errReply(CodeUnauthorized, "repo_id scope mismatch")
	}
	rows, err := s.Stores.Findings.List(ctx, req.RepoID)
	if err != nil {
		return rpcError(err)
	}
	out := make([]store.FindingRow, 0, len(rows))
	for _, r := range rows {
		if r != nil {
			out = append(out, *r)
		}
	}
	return okReply(FindingsListRes{Rows: out})
}

func (s *Server) findingsListByRun(ctx context.Context, env Envelope, _ string) Reply {
	var req FindingsListByRunReq
	if err := json.Unmarshal(env.Request, &req); err != nil {
		return errReply(CodeBadRequest, err.Error())
	}
	rows, err := s.Stores.Findings.ListByRun(ctx, req.RunID)
	if err != nil {
		return rpcError(err)
	}
	out := make([]store.FindingRow, 0, len(rows))
	for _, r := range rows {
		if r != nil {
			out = append(out, *r)
		}
	}
	return okReply(FindingsListRes{Rows: out})
}

func (s *Server) findingsFindByFingerprint(ctx context.Context, env Envelope, expectedRepo string) Reply {
	var req FindingsFindByFingerprintReq
	if err := json.Unmarshal(env.Request, &req); err != nil {
		return errReply(CodeBadRequest, err.Error())
	}
	if !scopeOK(req.RepoID, expectedRepo) {
		return errReply(CodeUnauthorized, "repo_id scope mismatch")
	}
	row, err := s.Stores.Findings.FindByFingerprintAndCreator(ctx, req.RepoID, req.Fingerprint, req.CreatedBy)
	if err != nil {
		return rpcError(err)
	}
	return okReply(FindingsGetRes{Row: *row})
}

func (s *Server) findingsUpdate(ctx context.Context, env Envelope, expectedRepo string) Reply {
	var req FindingsUpdateReq
	if err := json.Unmarshal(env.Request, &req); err != nil {
		return errReply(CodeBadRequest, err.Error())
	}
	if !scopeOK(req.Row.RepoID, expectedRepo) {
		return errReply(CodeUnauthorized, "repo_id scope mismatch")
	}
	if err := s.Stores.Findings.Update(ctx, &req.Row); err != nil {
		return rpcError(err)
	}
	return okReply(EmptyRes{})
}

func (s *Server) findingsUpdateStatus(ctx context.Context, env Envelope, expectedRepo string) Reply {
	var req FindingsUpdateStatusReq
	if err := json.Unmarshal(env.Request, &req); err != nil {
		return errReply(CodeBadRequest, err.Error())
	}
	// Resolve and verify scope.
	row, err := s.Stores.Findings.Get(ctx, req.ID)
	if err != nil {
		return rpcError(err)
	}
	if !scopeOK(row.RepoID, expectedRepo) {
		return errReply(CodeUnauthorized, "repo_id scope mismatch")
	}
	if err := s.Stores.Findings.UpdateStatus(ctx, req.ID, req.Status); err != nil {
		return rpcError(err)
	}
	return okReply(EmptyRes{})
}

func (s *Server) findingsAutoResolveMissing(ctx context.Context, env Envelope, expectedRepo string) Reply {
	var req FindingsAutoResolveMissingReq
	if err := json.Unmarshal(env.Request, &req); err != nil {
		return errReply(CodeBadRequest, err.Error())
	}
	if !scopeOK(req.RepoID, expectedRepo) {
		return errReply(CodeUnauthorized, "repo_id scope mismatch")
	}
	n, err := s.Stores.Findings.AutoResolveMissing(ctx, req.RepoID, req.SeenFingerprints)
	if err != nil {
		return rpcError(err)
	}
	return okReply(FindingsAutoResolveMissingRes{Count: n})
}

// --- memory handlers ---

func (s *Server) memoriesUpsert(ctx context.Context, env Envelope, expectedRepo string) Reply {
	var req MemoriesUpsertReq
	if err := json.Unmarshal(env.Request, &req); err != nil {
		return errReply(CodeBadRequest, err.Error())
	}
	if !scopeOK(req.Row.RepoID, expectedRepo) {
		return errReply(CodeUnauthorized, "repo_id scope mismatch")
	}
	if err := s.Stores.Memories.Upsert(ctx, &req.Row); err != nil {
		return rpcError(err)
	}
	return okReply(MemoriesUpsertRes{Row: req.Row})
}

func (s *Server) memoriesGet(ctx context.Context, env Envelope, expectedRepo string) Reply {
	var req MemoriesGetReq
	if err := json.Unmarshal(env.Request, &req); err != nil {
		return errReply(CodeBadRequest, err.Error())
	}
	if !scopeOK(req.RepoID, expectedRepo) {
		return errReply(CodeUnauthorized, "repo_id scope mismatch")
	}
	row, err := s.Stores.Memories.Get(ctx, req.RepoID, req.Name)
	if err != nil {
		return rpcError(err)
	}
	return okReply(MemoriesGetRes{Row: *row})
}

func (s *Server) memoriesList(ctx context.Context, env Envelope, expectedRepo string) Reply {
	var req MemoriesListReq
	if err := json.Unmarshal(env.Request, &req); err != nil {
		return errReply(CodeBadRequest, err.Error())
	}
	if !scopeOK(req.RepoID, expectedRepo) {
		return errReply(CodeUnauthorized, "repo_id scope mismatch")
	}
	rows, err := s.Stores.Memories.List(ctx, req.RepoID, req.Type)
	if err != nil {
		return rpcError(err)
	}
	out := make([]store.MemoryRow, 0, len(rows))
	for _, r := range rows {
		if r != nil {
			out = append(out, *r)
		}
	}
	return okReply(MemoriesListRes{Rows: out})
}

func (s *Server) memoriesDelete(ctx context.Context, env Envelope, expectedRepo string) Reply {
	var req MemoriesDeleteReq
	if err := json.Unmarshal(env.Request, &req); err != nil {
		return errReply(CodeBadRequest, err.Error())
	}
	if !scopeOK(req.RepoID, expectedRepo) {
		return errReply(CodeUnauthorized, "repo_id scope mismatch")
	}
	if err := s.Stores.Memories.Delete(ctx, req.RepoID, req.Name); err != nil {
		return rpcError(err)
	}
	return okReply(EmptyRes{})
}

func (s *Server) memoriesSearch(ctx context.Context, env Envelope, expectedRepo string) Reply {
	var req MemoriesSearchReq
	if err := json.Unmarshal(env.Request, &req); err != nil {
		return errReply(CodeBadRequest, err.Error())
	}
	if !scopeOK(req.RepoID, expectedRepo) {
		return errReply(CodeUnauthorized, "repo_id scope mismatch")
	}
	rows, err := s.Stores.Memories.Search(ctx, req.RepoID, req.Query)
	if err != nil {
		return rpcError(err)
	}
	out := make([]store.MemoryRow, 0, len(rows))
	for _, r := range rows {
		if r != nil {
			out = append(out, *r)
		}
	}
	return okReply(MemoriesListRes{Rows: out})
}

// --- exception handlers ---

func (s *Server) exceptionsCreate(ctx context.Context, env Envelope, expectedRepo string) Reply {
	var req ExceptionsCreateReq
	if err := json.Unmarshal(env.Request, &req); err != nil {
		return errReply(CodeBadRequest, err.Error())
	}
	if !scopeOK(req.Row.RepoID, expectedRepo) {
		return errReply(CodeUnauthorized, "repo_id scope mismatch")
	}
	if err := s.Stores.Exceptions.Create(ctx, &req.Row); err != nil {
		return rpcError(err)
	}
	return okReply(ExceptionsCreateRes{Row: req.Row})
}

func (s *Server) exceptionsGet(ctx context.Context, env Envelope, expectedRepo string) Reply {
	var req ExceptionsGetReq
	if err := json.Unmarshal(env.Request, &req); err != nil {
		return errReply(CodeBadRequest, err.Error())
	}
	row, err := s.Stores.Exceptions.Get(ctx, req.ID)
	if err != nil {
		return rpcError(err)
	}
	if !scopeOK(row.RepoID, expectedRepo) {
		return errReply(CodeUnauthorized, "repo_id scope mismatch")
	}
	return okReply(ExceptionsGetRes{Row: *row})
}

func (s *Server) exceptionsList(ctx context.Context, env Envelope, expectedRepo string) Reply {
	var req ExceptionsListReq
	if err := json.Unmarshal(env.Request, &req); err != nil {
		return errReply(CodeBadRequest, err.Error())
	}
	if !scopeOK(req.RepoID, expectedRepo) {
		return errReply(CodeUnauthorized, "repo_id scope mismatch")
	}
	rows, err := s.Stores.Exceptions.List(ctx, req.RepoID)
	if err != nil {
		return rpcError(err)
	}
	out := make([]store.ExceptionRow, 0, len(rows))
	for _, r := range rows {
		if r != nil {
			out = append(out, *r)
		}
	}
	return okReply(ExceptionsListRes{Rows: out})
}

func (s *Server) exceptionsDelete(ctx context.Context, env Envelope, _ string) Reply {
	var req ExceptionsDeleteReq
	if err := json.Unmarshal(env.Request, &req); err != nil {
		return errReply(CodeBadRequest, err.Error())
	}
	if err := s.Stores.Exceptions.Delete(ctx, req.ID); err != nil {
		return rpcError(err)
	}
	return okReply(EmptyRes{})
}

func (s *Server) exceptionsMatch(ctx context.Context, env Envelope, expectedRepo string) Reply {
	var req ExceptionsMatchReq
	if err := json.Unmarshal(env.Request, &req); err != nil {
		return errReply(CodeBadRequest, err.Error())
	}
	if !scopeOK(req.RepoID, expectedRepo) {
		return errReply(CodeUnauthorized, "repo_id scope mismatch")
	}
	row, err := s.Stores.Exceptions.Match(ctx, req.RepoID, req.Fingerprint, req.File, req.CWE, req.AgentName)
	if err != nil {
		return rpcError(err)
	}
	return okReply(ExceptionsMatchRes{Row: row})
}

// --- helpers ---

// scopeOK returns true when callerRepo matches the server's authorized
// repo. An empty expected (server didn't bind a repo) accepts any —
// that's only the case in tests that explicitly opt out.
func scopeOK(callerRepo, expected string) bool {
	if expected == "" {
		return true
	}
	return callerRepo == expected
}

// rpcError maps a store error into a Reply, preserving ErrNotFound as
// CodeNotFound so the client can rebuild a typed error.
func rpcError(err error) Reply {
	if errors.Is(err, store.ErrNotFound) {
		return Reply{Error: err.Error(), ErrorCode: CodeNotFound}
	}
	return Reply{Error: err.Error(), ErrorCode: CodeInternal}
}

func errReply(code, msg string) Reply {
	return Reply{Error: msg, ErrorCode: code}
}

func okReply(v any) Reply {
	b, err := json.Marshal(v)
	if err != nil {
		return Reply{Error: err.Error(), ErrorCode: CodeInternal}
	}
	return Reply{Result: b}
}
