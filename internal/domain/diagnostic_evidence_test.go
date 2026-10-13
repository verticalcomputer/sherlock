package domain

import (
	"testing"
	"time"
)

func diagnosticEvidenceRequest(targets ...DiagnosticTarget) DiagnosticRequest {
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	return DiagnosticRequest{
		RunID: "run-1", ClusterID: "cluster-a",
		Definition: DiagnosticDefinitionRef{PackID: "standard.readonly", PackVersion: "1.1.0", DefinitionID: "gpu.ecc_counters", DefinitionVersion: "1.0.0", DefinitionDigest: ChecksumSHA256([]byte("definition"))},
		Privilege:  DiagnosticUnprivileged, Targets: targets, RequestedBy: "investigator", IdempotencyKey: "key-1",
		RequestedAt: now, Deadline: now.Add(10 * time.Minute), MaxAttempts: 1,
	}
}

func diagnosticEvidenceAttempt(results ...DiagnosticTargetResult) DiagnosticAttemptResult {
	started := time.Date(2026, 8, 22, 10, 0, 5, 0, time.UTC)
	return DiagnosticAttemptResult{
		WorkID: "work-1", RunID: "run-1", Attempt: 1, RunnerID: "head-1", PlanDigest: ChecksumSHA256([]byte("plan")),
		StartedAt: started, CompletedAt: started.Add(2 * time.Second), Targets: results,
	}
}

func succeededTarget(name string, bytes int64) DiagnosticTargetResult {
	code := 0
	return DiagnosticTargetResult{Target: DiagnosticTarget(name), Status: DiagnosticTargetSucceeded, ExitCode: &code, StdoutBytes: bytes, StdoutSHA256: ChecksumSHA256([]byte(name))}
}

func failedTarget(name string) DiagnosticTargetResult {
	code := 1
	return DiagnosticTargetResult{Target: DiagnosticTarget(name), Status: DiagnosticTargetFailed, ExitCode: &code, ErrorCode: "EXIT_NONZERO"}
}

// A diagnostic result must be an ordinary evidence envelope, because every
// downstream stage -- citations, coverage projection, coalescing, the context
// builder, the replay harness -- already operates on envelopes and must not
// learn that this one came from a remote execution.
func TestDiagnosticEvidenceIsAnOrdinaryEnvelopeWithTypedCoverageAndAWindow(t *testing.T) {
	request := diagnosticEvidenceRequest("comp001", "comp002")
	attempt := diagnosticEvidenceAttempt(succeededTarget("comp001", 512), succeededTarget("comp002", 384))
	envelope, err := DiagnosticEvidenceForAttempt(request, attempt, 0)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Status() != EvidenceComplete {
		t.Fatalf("status = %s, want COMPLETE", envelope.Status())
	}
	coverage := envelope.Coverage()
	if !coverage.Complete() || len(coverage.Expected) != 3 {
		t.Fatalf("coverage = %+v", coverage)
	}
	// Coverage targets are typed, not opaque strings: the projection and the
	// admin report both key on the kind.
	kinds := map[EvidenceTargetKind]int{}
	for _, target := range coverage.Expected {
		kinds[target.Kind]++
	}
	if kinds[EvidenceTargetCluster] != 1 || kinds[EvidenceTargetNode] != 2 {
		t.Fatalf("expected one cluster and two node targets, got %v", kinds)
	}
	start, end := envelope.TimeRange().Start, envelope.TimeRange().End
	if !start.Equal(attempt.StartedAt) || !end.Equal(attempt.CompletedAt) || !end.After(start) {
		t.Fatalf("the observed window must be the execution window: %s to %s", start, end)
	}
	if envelope.Source().Operation != EvidenceOperationID("gpu.ecc_counters") {
		t.Fatalf("operation = %q, want the reviewed definition identifier", envelope.Source().Operation)
	}
	// The run is a diagnostic run, not a collection run. Recording it as the
	// latter meant every commit failed on evidence_envelopes' foreign key, so a
	// completed diagnostic could never become evidence at all.
	if envelope.Source().DiagnosticRunID != DiagnosticRunID("run-1") {
		t.Fatalf("diagnostic run attribution lost: %q", envelope.Source().DiagnosticRunID)
	}
	if envelope.Source().RunID != "" {
		t.Fatalf("a diagnostic must not claim a collection run: %q", envelope.Source().RunID)
	}
	// The source is named per cluster, not per pack: source_id is a global key,
	// so a pack-derived name would collide across clusters running the same pack.
	if envelope.Source().SourceID != DiagnosticEvidenceSourceID(request.ClusterID) {
		t.Fatalf("diagnostic source is not cluster-scoped: %q", envelope.Source().SourceID)
	}

	// The identity is derived from the run and plan, so re-projecting the same
	// attempt is idempotent and cannot create a second envelope.
	again, err := DiagnosticEvidenceForAttempt(request, attempt, 0)
	if err != nil {
		t.Fatal(err)
	}
	if again.ID() != envelope.ID() {
		t.Fatalf("re-projecting the same attempt produced %s and %s", envelope.ID(), again.ID())
	}
	other := diagnosticEvidenceAttempt(succeededTarget("comp001", 512), succeededTarget("comp002", 384))
	other.PlanDigest = ChecksumSHA256([]byte("another plan"))
	different, err := DiagnosticEvidenceForAttempt(request, other, 0)
	if err != nil {
		t.Fatal(err)
	}
	if different.ID() == envelope.ID() {
		t.Fatal("a different execution reused an evidence identity")
	}
}

// Partial and total failure must degrade the same way a collection does, so a
// host that answered still contributes evidence.
func TestDiagnosticEvidenceDegradesPerTarget(t *testing.T) {
	request := diagnosticEvidenceRequest("comp001", "comp002")

	partial, err := DiagnosticEvidenceForAttempt(request, diagnosticEvidenceAttempt(succeededTarget("comp001", 512), failedTarget("comp002")), 0)
	if err != nil {
		t.Fatal(err)
	}
	if partial.Status() != EvidencePartial {
		t.Fatalf("status = %s, want PARTIAL", partial.Status())
	}
	covered := partial.Coverage().Covered
	if len(covered) != 1 || covered[0].Kind != EvidenceTargetNode || covered[0].ID != "comp001" {
		t.Fatalf("the host that answered must be the covered target: %+v", covered)
	}

	none, err := DiagnosticEvidenceForAttempt(request, diagnosticEvidenceAttempt(failedTarget("comp001"), failedTarget("comp002")), 0)
	if err != nil {
		t.Fatal(err)
	}
	if none.Status() != EvidenceUnavailable || len(none.Coverage().Covered) != 0 {
		t.Fatalf("total failure = %s with %d covered", none.Status(), len(none.Coverage().Covered))
	}

	// Every host answering with nothing to report is an observation, not a
	// failure: it is how "no retired pages on any GPU" looks.
	empty, err := DiagnosticEvidenceForAttempt(request, diagnosticEvidenceAttempt(succeededTarget("comp001", 0), succeededTarget("comp002", 0)), 0)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Status() != EvidenceNoData || !empty.Coverage().Complete() {
		t.Fatalf("silent success = %s, complete=%t", empty.Status(), empty.Coverage().Complete())
	}
}

func TestDiagnosticEvidenceRefusesIncoherentInput(t *testing.T) {
	request := diagnosticEvidenceRequest("comp001")
	if _, err := DiagnosticEvidenceForAttempt(request, diagnosticEvidenceAttempt(succeededTarget("comp999", 1)), 0); err == nil {
		t.Fatal("a result for an unrequested target was accepted")
	}
	if _, err := DiagnosticEvidenceForAttempt(request, diagnosticEvidenceAttempt(), 0); err == nil {
		t.Fatal("an attempt covering no target was accepted")
	}
	foreign := diagnosticEvidenceAttempt(succeededTarget("comp001", 1))
	foreign.RunID = "run-2"
	if _, err := DiagnosticEvidenceForAttempt(request, foreign, 0); err == nil {
		t.Fatal("an attempt from a different run was accepted")
	}
	if _, err := DiagnosticEvidenceForAttempt(DiagnosticRequest{}, diagnosticEvidenceAttempt(succeededTarget("comp001", 1)), 0); err == nil {
		t.Fatal("an invalid request was accepted")
	}
}

// A live-state probe observes the instant it ran; a reviewed historical read
// observes the window its argv actually covers. Stamping a journal read with
// the execution instant understates it twice: coverage projection reports the
// investigated window as uninterrogated even though the read spanned it, and a
// reader takes days of events for a one-second sample.
func TestDiagnosticEvidenceWindowFollowsTheDeclaredLookback(t *testing.T) {
	request := diagnosticEvidenceRequest("comp003")
	attempt := diagnosticEvidenceAttempt(succeededTarget("comp003", 25656))

	live, err := DiagnosticEvidenceForAttempt(request, attempt, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !live.TimeRange().Start.Equal(attempt.StartedAt) || !live.TimeRange().End.Equal(attempt.CompletedAt) {
		t.Fatalf("live probe window = %s..%s, want the execution interval", live.TimeRange().Start, live.TimeRange().End)
	}

	lookback := 7 * 24 * time.Hour
	historical, err := DiagnosticEvidenceForAttempt(request, attempt, lookback)
	if err != nil {
		t.Fatal(err)
	}
	if !historical.TimeRange().Start.Equal(attempt.CompletedAt.Add(-lookback)) || !historical.TimeRange().End.Equal(attempt.CompletedAt) {
		t.Fatalf("historical window = %s..%s, want the seven days ending at completion", historical.TimeRange().Start, historical.TimeRange().End)
	}
	if !historical.CollectedAt().Equal(attempt.CompletedAt) {
		t.Fatalf("collection time moved with the observed window: %s", historical.CollectedAt())
	}
	// Identity addresses the execution, not the window it reports on, so the
	// same run keeps one evidence ID however far back its output reaches.
	if historical.ID() != live.ID() {
		t.Fatalf("lookback changed the evidence identity: %s vs %s", historical.ID(), live.ID())
	}

	// The bound exists because evidence is cited as though the whole window were
	// checked, so an unbounded lookback would assert an arbitrary past.
	if _, err := DiagnosticEvidenceForAttempt(request, attempt, -time.Second); err == nil {
		t.Fatal("a negative lookback was accepted")
	}
	if _, err := DiagnosticEvidenceForAttempt(request, attempt, MaximumDiagnosticObservationLookback+time.Second); err == nil {
		t.Fatal("a lookback beyond the reviewed bound was accepted")
	}
}
