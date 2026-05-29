package worker

// RunState is the canonical run lifecycle. Allowed transitions:
//
//	queued → cloning → indexing → running → reporting → completed
//	                                                  ↘ failed
//	                                                  ↘ cancelled
//
// Failed/cancelled may be entered from any earlier state.
type RunState string

const (
	StateQueued    RunState = "queued"
	StateCloning   RunState = "cloning"
	StateIndexing  RunState = "indexing"
	StateRunning   RunState = "running"
	StateReporting RunState = "reporting"
	StateCompleted RunState = "completed"
	StateFailed    RunState = "failed"
	StateCancelled RunState = "cancelled"
)

// IsTerminal reports whether the state ends the run.
func (s RunState) IsTerminal() bool {
	return s == StateCompleted || s == StateFailed || s == StateCancelled
}
