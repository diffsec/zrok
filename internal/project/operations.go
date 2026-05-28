package project

// InitRequest is the input to Init. RootPath is the project root to write
// .quokka into.
type InitRequest struct {
	RootPath string
}

// Init creates a fresh .quokka scaffold at the given root.
func Init(req InitRequest) (*Project, error) {
	return Initialize(req.RootPath)
}

// OnboardAutoRequest carries an existing Project to onboard.
type OnboardAutoRequest struct {
	Project *Project
}

// OnboardAuto runs the non-interactive onboarding flow (tech detection,
// classification, initial memory seeding).
func OnboardAuto(req OnboardAutoRequest) (*OnboardingResult, error) {
	o := NewOnboarder(req.Project)
	return o.RunAuto()
}

// OnboardAgentRequest carries an existing Project for the agent-driven
// onboarding flow.
type OnboardAgentRequest struct {
	Project *Project
}

// OnboardAgent runs the agent-friendly onboarding flow.
func OnboardAgent(req OnboardAgentRequest) (*AgentOnboardingResult, error) {
	o := NewOnboarder(req.Project)
	return o.RunAgent()
}
