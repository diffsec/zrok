package jobs

import (
	"context"
	"errors"
)

// IndexRepo is a placeholder for the v1 incremental indexer. PR-4 ships a
// no-op so the worker handles the job type without crashing; PR-6's
// end-to-end demo wires the actual indexer.
func IndexRepo(ctx context.Context, deps *Deps, payload []byte) error {
	if deps == nil {
		return errors.New("IndexRepo: nil deps")
	}
	deps.Log.Info("IndexRepo: not yet implemented (stub)")
	return nil
}
