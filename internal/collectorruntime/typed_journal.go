package collectorruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func (j *Journal) beginTyped(lease domain.TypedWorkLease) (journalEntry, bool, error) {
	p := lease.Plan
	lease.Lease.Work.Task = domain.CollectionTask{RunID: p.RunID, ClusterID: p.ClusterID, SourceID: p.SourceID, Query: domain.QueryKind(p.Operation),
		ScheduledFor: p.ScheduledFor, Deadline: p.Deadline, MaxSeries: p.Limits.MaxRecords, MaxBytes: p.Limits.MaxBytes, IdempotencyKey: p.IdempotencyKey}
	return j.beginEntry(lease.Lease, &lease.Plan)
}

func (j *Journal) storeTypedResult(result domain.TypedCollectorResult) error {
	payload, err := domain.EncodeTypedCollectorResult(result)
	if err != nil {
		return fmt.Errorf("typed journal result is invalid or exceeds its assigned limit")
	}
	return j.storeResultPayload(result.Plan.RunID, result.Status, payload)
}

func loadJournalTypedResult(ctx context.Context, q journalQuerier, runID domain.RunID, digest []byte) (*domain.TypedCollectorResult, error) {
	var payload []byte
	if err := q.QueryRowContext(ctx, `SELECT payload FROM results WHERE run_id=?`, string(runID)).Scan(&payload); err != nil {
		return nil, fmt.Errorf("read typed journal result: %w", err)
	}
	actual := sha256.Sum256(payload)
	if !bytes.Equal(actual[:], digest) {
		return nil, fmt.Errorf("typed journal result failed integrity verification")
	}
	result, err := domain.DecodeTypedCollectorResult(payload)
	if err != nil {
		return nil, fmt.Errorf("typed journal result failed validation")
	}
	return &result, nil
}
