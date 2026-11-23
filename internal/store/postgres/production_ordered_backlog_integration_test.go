//go:build integration && !race

package postgres

import "testing"

// Race instrumentation changes latency. Qualify a longer backlog against the
// actual per-GPU time limit while generating both transitions in one pass.
func TestProductionOrderedOpenAndRecoveryInOneBatch(t *testing.T) {
	runOrderedRecoveryAtomicRestart(t, false)
}
