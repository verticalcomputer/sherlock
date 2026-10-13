package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func (s *CollectorControlStore) UploadResultChunk(ctx context.Context, collectorID domain.CollectorID, chunk collectorcontrol.ResultChunk) (collectorcontrol.ChunkOutcome, error) {
	if collectorID == "" {
		return collectorcontrol.ChunkOutcome{}, fmt.Errorf("collector identifier is required")
	}
	if err := collectorcontrol.ValidateResultChunk(chunk); err != nil {
		return collectorcontrol.ChunkOutcome{}, err
	}
	expectedChecksum, _ := hex.DecodeString(chunk.SHA256)
	actualChecksum := sha256.Sum256(chunk.Payload)
	if subtle.ConstantTimeCompare(expectedChecksum, actualChecksum[:]) != 1 {
		return collectorcontrol.ChunkOutcome{}, resultConflict("result chunk SHA-256 does not match its payload")
	}
	tokenHash := sha256.Sum256([]byte(chunk.LeaseToken))
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return collectorcontrol.ChunkOutcome{}, fmt.Errorf("begin result chunk upload: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	lease, err := lockResultLease(ctx, tx, chunk.WorkID, chunk.Attempt)
	if err != nil {
		return collectorcontrol.ChunkOutcome{}, err
	}
	if lease.typedPlan != nil {
		return collectorcontrol.ChunkOutcome{}, resultConflict("typed work requires v2 result ingestion")
	}
	if lease.collectorID != collectorID || subtle.ConstantTimeCompare(lease.tokenHash, tokenHash[:]) != 1 {
		return collectorcontrol.ChunkOutcome{}, invalidResultLease("collector result lease identity is invalid")
	}

	var storedPayload, storedChecksum []byte
	err = tx.QueryRow(ctx, `SELECT payload, sha256 FROM collector_result_chunks WHERE work_id=$1 AND attempt=$2 AND chunk_index=$3`, chunk.WorkID, chunk.Attempt, chunk.Index).Scan(&storedPayload, &storedChecksum)
	if err != nil && err != pgx.ErrNoRows {
		return collectorcontrol.ChunkOutcome{}, fmt.Errorf("load existing result chunk: %w", err)
	}
	if err == nil {
		if !bytes.Equal(storedPayload, chunk.Payload) || subtle.ConstantTimeCompare(storedChecksum, actualChecksum[:]) != 1 {
			return collectorcontrol.ChunkOutcome{}, resultConflict("result chunk index %d conflicts with its immutable prior upload", chunk.Index)
		}
		if err := tx.Commit(ctx); err != nil {
			return collectorcontrol.ChunkOutcome{}, fmt.Errorf("commit duplicate result chunk: %w", err)
		}
		return collectorcontrol.ChunkOutcome{PreviouslyUploaded: true}, nil
	}
	if lease.finalized {
		return collectorcontrol.ChunkOutcome{}, resultConflict("collector result is already finalized")
	}
	if err := validateActiveResultLease(lease); err != nil {
		return collectorcontrol.ChunkOutcome{}, err
	}

	var chunkCount int
	var byteCount int64
	if err := tx.QueryRow(ctx, `SELECT count(*), COALESCE(sum(byte_count), 0) FROM collector_result_chunks WHERE work_id=$1 AND attempt=$2`, chunk.WorkID, chunk.Attempt).Scan(&chunkCount, &byteCount); err != nil {
		return collectorcontrol.ChunkOutcome{}, fmt.Errorf("measure uploaded result chunks: %w", err)
	}
	if chunk.Index != chunkCount {
		return collectorcontrol.ChunkOutcome{}, resultConflict("result chunks must be uploaded sequentially; expected index %d", chunkCount)
	}
	if chunkCount >= collectorcontrol.MaxResultChunks || byteCount+int64(len(chunk.Payload)) > lease.work.Task.MaxBytes {
		return collectorcontrol.ChunkOutcome{}, resultConflict("result chunks exceed the assigned count or byte limit")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO collector_result_chunks (work_id, attempt, chunk_index, payload, sha256, byte_count) VALUES ($1,$2,$3,$4,$5,$6)`, chunk.WorkID, chunk.Attempt, chunk.Index, chunk.Payload, actualChecksum[:], len(chunk.Payload)); err != nil {
		return collectorcontrol.ChunkOutcome{}, fmt.Errorf("insert result chunk %d: %w", chunk.Index, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return collectorcontrol.ChunkOutcome{}, fmt.Errorf("commit result chunk %d: %w", chunk.Index, err)
	}
	return collectorcontrol.ChunkOutcome{}, nil
}

func (s *CollectorControlStore) FinalizeResult(ctx context.Context, collectorID domain.CollectorID, finalization collectorcontrol.ResultFinalization) (collectorcontrol.FinalizeOutcome, error) {
	if collectorID == "" {
		return collectorcontrol.FinalizeOutcome{}, fmt.Errorf("collector identifier is required")
	}
	if err := collectorcontrol.ValidateResultFinalization(finalization); err != nil {
		return collectorcontrol.FinalizeOutcome{}, err
	}
	expectedChecksum, _ := hex.DecodeString(finalization.SHA256)
	tokenHash := sha256.Sum256([]byte(finalization.LeaseToken))
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return collectorcontrol.FinalizeOutcome{}, fmt.Errorf("begin result finalization: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var cluster domain.ClusterID
	var repairWork bool
	if err = tx.QueryRow(ctx, `SELECT cluster_id FROM collector_work_items WHERE work_id=$1`, finalization.WorkID).Scan(&cluster); err != nil {
		return collectorcontrol.FinalizeOutcome{}, invalidResultLease("collector result work does not exist")
	}
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM collection_repair_requests WHERE work_id=$1)`, finalization.WorkID).Scan(&repairWork); err != nil {
		return collectorcontrol.FinalizeOutcome{}, fmt.Errorf("inspect repair result authority: %w", err)
	}
	if repairWork {
		if err = LockRepairAuthority(ctx, tx, cluster); err != nil {
			return collectorcontrol.FinalizeOutcome{}, fmt.Errorf("lock repair authority for result finalization: %w", err)
		}
	}

	lease, err := lockResultLease(ctx, tx, finalization.WorkID, finalization.Attempt)
	if err != nil {
		return collectorcontrol.FinalizeOutcome{}, err
	}
	if lease.typedPlan != nil {
		return collectorcontrol.FinalizeOutcome{}, resultConflict("typed work requires v2 result ingestion")
	}
	if lease.collectorID != collectorID || subtle.ConstantTimeCompare(lease.tokenHash, tokenHash[:]) != 1 {
		return collectorcontrol.FinalizeOutcome{}, invalidResultLease("collector result lease identity is invalid")
	}
	if lease.finalized {
		if lease.finalizedRunID != finalization.RunID || lease.finalizedStatus != finalization.Status || lease.finalizedChunks != finalization.ChunkCount || lease.finalizedBytes != finalization.Bytes || subtle.ConstantTimeCompare(lease.finalizedChecksum, expectedChecksum) != 1 {
			return collectorcontrol.FinalizeOutcome{}, resultConflict("result finalization conflicts with its immutable prior outcome")
		}
		if err := tx.Commit(ctx); err != nil {
			return collectorcontrol.FinalizeOutcome{}, fmt.Errorf("commit duplicate result finalization: %w", err)
		}
		return collectorcontrol.FinalizeOutcome{RunID: finalization.RunID, Status: finalization.Status, SHA256: finalization.SHA256, PreviouslyFinalized: true}, nil
	}
	if err := validateActiveResultLease(lease); err != nil {
		return collectorcontrol.FinalizeOutcome{}, err
	}
	if finalization.Bytes > lease.work.Task.MaxBytes {
		return collectorcontrol.FinalizeOutcome{}, resultConflict("final result exceeds its assigned byte limit")
	}

	rows, err := tx.Query(ctx, `SELECT chunk_index, payload, sha256 FROM collector_result_chunks WHERE work_id=$1 AND attempt=$2 ORDER BY chunk_index`, finalization.WorkID, finalization.Attempt)
	if err != nil {
		return collectorcontrol.FinalizeOutcome{}, fmt.Errorf("load result chunks: %w", err)
	}
	var payload []byte
	chunkCount := 0
	for rows.Next() {
		var index int
		var chunkPayload, storedChecksum []byte
		if err := rows.Scan(&index, &chunkPayload, &storedChecksum); err != nil {
			rows.Close()
			return collectorcontrol.FinalizeOutcome{}, fmt.Errorf("scan result chunk: %w", err)
		}
		actual := sha256.Sum256(chunkPayload)
		if index != chunkCount || subtle.ConstantTimeCompare(storedChecksum, actual[:]) != 1 {
			rows.Close()
			return collectorcontrol.FinalizeOutcome{}, resultConflict("stored result chunk sequence or checksum is invalid")
		}
		payload = append(payload, chunkPayload...)
		chunkCount++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return collectorcontrol.FinalizeOutcome{}, fmt.Errorf("iterate result chunks: %w", err)
	}
	rows.Close()
	if chunkCount != finalization.ChunkCount || int64(len(payload)) != finalization.Bytes {
		return collectorcontrol.FinalizeOutcome{}, resultConflict("result finalization chunk count or byte total does not match uploaded data")
	}
	actualChecksum := sha256.Sum256(payload)
	if subtle.ConstantTimeCompare(expectedChecksum, actualChecksum[:]) != 1 {
		return collectorcontrol.FinalizeOutcome{}, resultConflict("final result SHA-256 does not match uploaded data")
	}
	document, err := domain.DecodeCollectorResult(payload)
	if err != nil {
		return collectorcontrol.FinalizeOutcome{}, resultConflict("%v", err)
	}
	if err := domain.ValidateCollectorResult(document, lease.work, finalization.Attempt); err != nil {
		return collectorcontrol.FinalizeOutcome{}, resultConflict("%v", err)
	}
	if document.Result.Task.RunID != finalization.RunID || document.Result.Status != finalization.Status {
		return collectorcontrol.FinalizeOutcome{}, resultConflict("result finalization identity or status does not match its document")
	}
	inserted, err := recordResultTx(ctx, tx, document.Result)
	if err != nil {
		return collectorcontrol.FinalizeOutcome{}, err
	}
	if !inserted {
		return collectorcontrol.FinalizeOutcome{}, resultConflict("collection result conflicts with a previously recorded run")
	}
	attemptStatus := domain.AttemptSucceeded
	workStatus := domain.WorkSucceeded
	if document.Result.Status == domain.ResultFailed {
		attemptStatus = domain.AttemptFailed
		workStatus = domain.WorkFailed
	}
	if _, err := tx.Exec(ctx, `INSERT INTO collector_result_ingestions (work_id, attempt, collector_id, run_id, result_status, chunk_count, byte_count, sha256) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, finalization.WorkID, finalization.Attempt, collectorID, finalization.RunID, finalization.Status, finalization.ChunkCount, finalization.Bytes, actualChecksum[:]); err != nil {
		return collectorcontrol.FinalizeOutcome{}, fmt.Errorf("record result ingestion: %w", err)
	}
	if command, err := tx.Exec(ctx, `UPDATE collector_work_attempts SET status=$3, completed_at=clock_timestamp() WHERE work_id=$1 AND attempt=$2 AND status IN ('CLAIMED','STARTED')`, finalization.WorkID, finalization.Attempt, attemptStatus); err != nil || command.RowsAffected() != 1 {
		if err == nil {
			err = fmt.Errorf("attempt changed concurrently")
		}
		return collectorcontrol.FinalizeOutcome{}, fmt.Errorf("complete collector work attempt: %w", err)
	}
	if command, err := tx.Exec(ctx, `UPDATE collector_work_items SET status=$2, completed_at=clock_timestamp() WHERE work_id=$1 AND status='LEASED'`, finalization.WorkID, workStatus); err != nil || command.RowsAffected() != 1 {
		if err == nil {
			err = fmt.Errorf("work changed concurrently")
		}
		return collectorcontrol.FinalizeOutcome{}, fmt.Errorf("complete collector work: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return collectorcontrol.FinalizeOutcome{}, fmt.Errorf("commit result finalization: %w", err)
	}
	return collectorcontrol.FinalizeOutcome{RunID: finalization.RunID, Status: finalization.Status, SHA256: finalization.SHA256}, nil
}

func (s *CollectorControlStore) LoadFinalizedResult(ctx context.Context, workID domain.WorkID) (domain.CollectionResult, bool, error) {
	if workID == "" {
		return domain.CollectionResult{}, false, fmt.Errorf("work identifier is required")
	}
	return s.loadFinalizedResult(ctx, `i.work_id=$1`, workID)
}

func (s *CollectorControlStore) LoadFinalizedResultByRun(ctx context.Context, runID domain.RunID) (domain.CollectionResult, bool, error) {
	if runID == "" {
		return domain.CollectionResult{}, false, fmt.Errorf("run identifier is required")
	}
	return s.loadFinalizedResult(ctx, `i.run_id=$1`, runID)
}

func (s *CollectorControlStore) loadFinalizedResult(ctx context.Context, predicate string, identifier any) (domain.CollectionResult, bool, error) {
	query := `
		SELECT c.payload
		FROM collector_result_ingestions i
		JOIN collector_result_chunks c USING (work_id, attempt)
		WHERE ` + predicate + `
		ORDER BY c.chunk_index`
	rows, err := s.pool.Query(ctx, query, identifier)
	if err != nil {
		return domain.CollectionResult{}, false, fmt.Errorf("load finalized result chunks: %w", err)
	}
	defer rows.Close()
	var payload []byte
	for rows.Next() {
		var chunk []byte
		if err := rows.Scan(&chunk); err != nil {
			return domain.CollectionResult{}, false, fmt.Errorf("scan finalized result chunk: %w", err)
		}
		payload = append(payload, chunk...)
	}
	if err := rows.Err(); err != nil {
		return domain.CollectionResult{}, false, fmt.Errorf("iterate finalized result chunks: %w", err)
	}
	if len(payload) == 0 {
		return domain.CollectionResult{}, false, nil
	}
	document, err := domain.DecodeCollectorResult(payload)
	if err != nil {
		return domain.CollectionResult{}, false, fmt.Errorf("decode stored finalized result: %w", err)
	}
	return document.Result, true, nil
}

type resultLeaseState struct {
	work              domain.CollectorWork
	collectorID       domain.CollectorID
	tokenHash         []byte
	attemptStatus     domain.AttemptStatus
	leaseExpires      time.Time
	leaseActive       bool
	currentAttempt    int
	attempt           int
	finalized         bool
	finalizedRunID    domain.RunID
	finalizedStatus   domain.ResultStatus
	finalizedChunks   int
	finalizedBytes    int64
	finalizedChecksum []byte
	typedPlan         []byte
}

func lockResultLease(ctx context.Context, tx pgx.Tx, workID domain.WorkID, attempt int) (resultLeaseState, error) {
	var state resultLeaseState
	state.attempt = attempt
	var query domain.QueryKind
	var rangeStartAt, rangeEndAt *time.Time
	var rangeStepSeconds *float64
	var finalizedRunID *string
	var finalizedStatus *string
	var finalizedChunks *int
	var finalizedBytes *int64
	err := tx.QueryRow(ctx, `
		SELECT w.work_id, w.run_id, w.cluster_id, w.source_id, w.query_kind, w.node_filter,
		       w.range_start, w.range_end, w.range_step_seconds, w.scheduled_for, w.deadline,
		       w.max_series, w.max_bytes, w.idempotency_key, w.status, w.available_at,
		       w.work_expires_at, w.next_attempt,
		       a.collector_id, a.lease_token_hash, a.status, a.lease_expires_at,
		       a.lease_expires_at > clock_timestamp(),
		       i.run_id, i.result_status, i.chunk_count, i.byte_count, i.sha256, w.typed_plan
		FROM collector_work_attempts a
		JOIN collector_work_items w USING (work_id)
		LEFT JOIN collector_result_ingestions i USING (work_id, attempt)
		WHERE a.work_id=$1 AND a.attempt=$2
		FOR UPDATE OF a, w`, workID, attempt).Scan(
		&state.work.WorkID, &state.work.Task.RunID, &state.work.Task.ClusterID, &state.work.Task.SourceID,
		&query, &state.work.Task.Node, &rangeStartAt, &rangeEndAt, &rangeStepSeconds,
		&state.work.Task.ScheduledFor, &state.work.Task.Deadline, &state.work.Task.MaxSeries,
		&state.work.Task.MaxBytes, &state.work.Task.IdempotencyKey, &state.work.Status,
		&state.work.AvailableAt, &state.work.WorkExpiresAt, &state.currentAttempt,
		&state.collectorID, &state.tokenHash, &state.attemptStatus, &state.leaseExpires, &state.leaseActive,
		&finalizedRunID, &finalizedStatus, &finalizedChunks, &finalizedBytes, &state.finalizedChecksum, &state.typedPlan)
	if err == pgx.ErrNoRows {
		return resultLeaseState{}, invalidResultLease("collector result work attempt does not exist")
	}
	if err != nil {
		return resultLeaseState{}, fmt.Errorf("load collector result lease: %w", err)
	}
	state.work.Task.Query = query
	if rangeStartAt != nil {
		state.work.Task.Range = &domain.CollectionRange{Start: rangeStartAt.UTC(), End: rangeEndAt.UTC(), Step: time.Duration(*rangeStepSeconds * float64(time.Second))}
	}
	if finalizedRunID != nil {
		state.finalized = true
		state.finalizedRunID = domain.RunID(*finalizedRunID)
		state.finalizedStatus = domain.ResultStatus(*finalizedStatus)
		state.finalizedChunks = *finalizedChunks
		state.finalizedBytes = *finalizedBytes
	}
	return state, nil
}

func validateActiveResultLease(state resultLeaseState) error {
	if state.work.Status != domain.WorkLeased || state.currentAttempt != state.attempt+1 || (state.attemptStatus != domain.AttemptClaimed && state.attemptStatus != domain.AttemptStarted) || !state.leaseActive {
		return invalidResultLease("collector result lease is stale, terminal, or expired")
	}
	return nil
}

func invalidResultLease(message string, arguments ...any) error {
	return fmt.Errorf("%w: %s", collectorcontrol.ErrWorkLeaseInvalid, fmt.Sprintf(message, arguments...))
}

func resultConflict(message string, arguments ...any) error {
	return fmt.Errorf("%w: %s", collectorcontrol.ErrResultConflict, fmt.Sprintf(message, arguments...))
}
