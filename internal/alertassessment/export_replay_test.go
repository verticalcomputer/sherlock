package alertassessment

// SetReplayHiddenBoundaries selects the previous reconstruction, as the
// reference for differential tests.
func SetReplayHiddenBoundaries(e *Engine, on bool) { e.replayHiddenBoundaries = on }

// VisibleInputReplayEnabled reports the engine's opt-in decision.
func VisibleInputReplayEnabled(e *Engine) bool { return e.visibleReplayCategory() != nil }
