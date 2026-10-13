package postgres

import (
	"context"
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const kernelXIDArtifactRetention = 30 * 24 * time.Hour

// KernelXIDArtifactStore is deliberately separate from the public evidence
// and model-context stores. Its methods require the complete cluster-scoped
// diagnostic binding; no API or investigation tool is wired to this reader.
type KernelXIDArtifactStore struct {
	pool      *pgxpool.Pool
	retention time.Duration
}

func NewKernelXIDArtifactStore(pool *pgxpool.Pool) (*KernelXIDArtifactStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("PostgreSQL pool is required")
	}
	return newKernelXIDArtifactStore(pool, kernelXIDArtifactRetention)
}

func newKernelXIDArtifactStore(pool *pgxpool.Pool, retention time.Duration) (*KernelXIDArtifactStore, error) {
	if pool == nil || retention <= 0 || retention > kernelXIDArtifactRetention {
		return nil, fmt.Errorf("PostgreSQL pool and bounded kernel XID artifact retention are required")
	}
	return &KernelXIDArtifactStore{pool: pool, retention: retention}, nil
}

type KernelXIDArtifactScope struct {
	ClusterID domain.ClusterID
	RunID     domain.DiagnosticRunID
	WorkID    domain.DiagnosticWorkID
	Attempt   int
	Target    domain.DiagnosticTarget
}

func (scope KernelXIDArtifactScope) validate() error {
	if scope.ClusterID == "" || scope.RunID == "" || scope.WorkID == "" || scope.Target == "" || scope.Attempt < 1 || scope.Attempt > 3 {
		return fmt.Errorf("kernel XID artifact scope is invalid")
	}
	return nil
}

type KernelXIDArtifactWrite struct {
	Scope              KernelXIDArtifactScope
	Definition         domain.DiagnosticDefinitionRef
	SourceStdoutSHA256 domain.SHA256
	Artifact           domain.KernelXIDArtifact
}

type KernelXIDArtifactState string

const (
	KernelXIDArtifactAvailable KernelXIDArtifactState = "AVAILABLE"
	KernelXIDArtifactMissing   KernelXIDArtifactState = "MISSING"
	KernelXIDArtifactExpired   KernelXIDArtifactState = "EXPIRED"
	KernelXIDArtifactDeleted   KernelXIDArtifactState = "DELETED"
	KernelXIDArtifactCorrupt   KernelXIDArtifactState = "CORRUPT"
)

type KernelXIDArtifactRead struct {
	State KernelXIDArtifactState
	Gaps  []domain.KernelXIDArtifactGap
	// Artifact is set only for a checksum-verified, canonical stored payload.
	Artifact *domain.KernelXIDArtifact
}

// Store persists an exact idempotent replay once. It re-loads the signed
// diagnostic binding and original source digest from PostgreSQL before writing
// so caller-supplied IDs cannot rebind an artifact to another run or target.
func (store *KernelXIDArtifactStore) Store(ctx context.Context, input KernelXIDArtifactWrite) (bool, error) {
	if err := input.Scope.validate(); err != nil {
		return false, err
	}
	if err := input.Definition.Validate(); err != nil {
		return false, fmt.Errorf("kernel XID artifact definition: %w", err)
	}
	if input.Definition.DefinitionID != "node.kernel_xid" || input.Definition.DefinitionVersion != "2.0.0" || input.SourceStdoutSHA256 == (domain.SHA256{}) {
		return false, application.ErrKernelXIDArtifactBinding
	}
	expectedBinding := domain.KernelXIDArtifactBinding{
		ClusterID: input.Scope.ClusterID, RunID: input.Scope.RunID, WorkID: input.Scope.WorkID, Attempt: input.Scope.Attempt, Target: input.Scope.Target,
		PackID: input.Definition.PackID, PackVersion: input.Definition.PackVersion, DefinitionID: input.Definition.DefinitionID,
		DefinitionVersion: input.Definition.DefinitionVersion, DefinitionDigest: input.Definition.DefinitionDigest, SourceStdoutSHA256: input.SourceStdoutSHA256,
	}
	bound, err := domain.ParseKernelXIDArtifact(input.Artifact.Bytes())
	actualBinding, boundOK := bound.Binding()
	if err != nil || !boundOK || bound.SHA256() != domain.ChecksumSHA256(bound.Bytes()) {
		return false, application.ErrKernelXIDArtifactScreening
	}
	if !domain.KernelXIDArtifactBindingsEqual(actualBinding, expectedBinding) {
		return false, application.ErrKernelXIDArtifactBinding
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, fmt.Errorf("begin kernel XID artifact write: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var storedDefinition domain.DiagnosticDefinitionRef
	var storedDefinitionDigest, storedSource []byte
	var stdoutTruncated bool
	var stdoutState domain.StdoutTransformationState
	var targetStatus domain.DiagnosticTargetStatus
	err = tx.QueryRow(ctx, `
		SELECT r.pack_id, r.pack_version, r.definition_id, r.definition_version, r.definition_digest,
		       t.stdout_sha256, t.stdout_truncated, t.stdout_transformation_state, t.status
		FROM diagnostic_runs r
		JOIN diagnostic_work_items w ON w.run_id=r.run_id
		JOIN diagnostic_target_results t ON t.work_id=w.work_id
		WHERE r.cluster_id=$1 AND r.run_id=$2 AND w.work_id=$3 AND t.attempt=$4 AND t.target=$5
		FOR KEY SHARE OF r, w, t`, input.Scope.ClusterID, input.Scope.RunID, input.Scope.WorkID, input.Scope.Attempt, input.Scope.Target).
		Scan(&storedDefinition.PackID, &storedDefinition.PackVersion, &storedDefinition.DefinitionID, &storedDefinition.DefinitionVersion, &storedDefinitionDigest, &storedSource, &stdoutTruncated, &stdoutState, &targetStatus)
	if err == pgx.ErrNoRows {
		return false, application.ErrKernelXIDArtifactNotFound
	}
	if err != nil {
		return false, fmt.Errorf("load kernel XID artifact binding: %w", err)
	}
	if len(storedDefinitionDigest) != len(storedDefinition.DefinitionDigest) || len(storedSource) != len(input.SourceStdoutSHA256) {
		return false, application.ErrKernelXIDArtifactBinding
	}
	copy(storedDefinition.DefinitionDigest[:], storedDefinitionDigest)
	if storedDefinition != input.Definition || subtle.ConstantTimeCompare(storedSource, input.SourceStdoutSHA256[:]) != 1 {
		return false, application.ErrKernelXIDArtifactBinding
	}
	if !artifactAccountsForSource(bound, stdoutTruncated, stdoutState) {
		return false, application.ErrKernelXIDArtifactBinding
	}
	if !artifactMatchesDiagnosticTargetStatus(bound, targetStatus) {
		return false, application.ErrKernelXIDArtifactBinding
	}

	command, err := tx.Exec(ctx, `
		WITH write_time AS MATERIALIZED (SELECT clock_timestamp() AS value)
		INSERT INTO kernel_xid_artifacts (
			cluster_id,run_id,work_id,attempt,target,pack_id,pack_version,definition_id,definition_version,definition_digest,
			source_stdout_sha256,artifact_schema_version,parser_version,redaction_version,artifact_sha256,artifact_bytes,event_count,truncated,state,created_at,expires_at
		) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'AVAILABLE',write_time.value,write_time.value+($19 * interval '1 microsecond') FROM write_time
		ON CONFLICT (work_id,attempt,target) DO NOTHING`,
		input.Scope.ClusterID, input.Scope.RunID, input.Scope.WorkID, input.Scope.Attempt, input.Scope.Target,
		input.Definition.PackID, input.Definition.PackVersion, input.Definition.DefinitionID, input.Definition.DefinitionVersion, input.Definition.DefinitionDigest[:],
		input.SourceStdoutSHA256[:], domain.KernelXIDArtifactSchemaVersion, domain.KernelXIDArtifactParserVersion, domain.KernelXIDArtifactRedactionVersion,
		artifactChecksumBytes(bound), bound.Bytes(), bound.EventCount(), bound.Truncated(), store.retention.Microseconds())
	if err != nil {
		return false, fmt.Errorf("insert kernel XID artifact: %w", err)
	}
	if command.RowsAffected() == 0 {
		prior, err := store.readLocked(ctx, tx, input.Scope)
		if err != nil {
			return false, err
		}
		if prior.State != KernelXIDArtifactAvailable || prior.Artifact == nil || prior.Artifact.SHA256() != bound.SHA256() || !subtleBytesEqual(prior.Artifact.Bytes(), bound.Bytes()) {
			return false, application.ErrKernelXIDArtifactConflict
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit kernel XID artifact: %w", err)
	}
	return command.RowsAffected() == 1, nil
}

func subtleBytesEqual(left, right []byte) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare(left, right) == 1
}
func artifactChecksumBytes(artifact domain.KernelXIDArtifact) []byte {
	checksum := artifact.SHA256()
	return checksum[:]
}

func artifactAccountsForSource(artifact domain.KernelXIDArtifact, truncated bool, state domain.StdoutTransformationState) bool {
	if truncated && !artifact.HasGap(domain.KernelXIDArtifactGapOutputTruncated) {
		return false
	}
	switch state {
	case domain.StdoutTransformationUnmodified:
		return true
	case domain.StdoutTransformationTransformed:
		return artifact.HasGap(domain.KernelXIDArtifactGapOutputTransformed)
	default:
		return artifact.HasGap(domain.KernelXIDArtifactGapOutputUnknown)
	}
}

func artifactMatchesDiagnosticTargetStatus(artifact domain.KernelXIDArtifact, status domain.DiagnosticTargetStatus) bool {
	targetGaps := []domain.KernelXIDArtifactGap{
		domain.KernelXIDArtifactGapTargetUnavailable,
		domain.KernelXIDArtifactGapTargetFailed,
		domain.KernelXIDArtifactGapTargetTimedOut,
		domain.KernelXIDArtifactGapTargetRejected,
	}
	switch status {
	case domain.DiagnosticTargetSucceeded:
		for _, gap := range targetGaps {
			if artifact.HasGap(gap) {
				return false
			}
		}
		return true
	case domain.DiagnosticTargetFailed:
		return artifact.Disposition() == domain.KernelXIDArtifactUnavailable && artifact.EventCount() == 0 && artifactHasExactGaps(artifact, domain.KernelXIDArtifactGapTargetUnavailable, domain.KernelXIDArtifactGapTargetFailed)
	case domain.DiagnosticTargetTimedOut:
		return artifact.Disposition() == domain.KernelXIDArtifactUnavailable && artifact.EventCount() == 0 && artifactHasExactGaps(artifact, domain.KernelXIDArtifactGapTargetUnavailable, domain.KernelXIDArtifactGapTargetTimedOut)
	case domain.DiagnosticTargetRejected:
		return artifact.Disposition() == domain.KernelXIDArtifactUnavailable && artifact.EventCount() == 0 && artifactHasExactGaps(artifact, domain.KernelXIDArtifactGapTargetUnavailable, domain.KernelXIDArtifactGapTargetRejected)
	default:
		return false
	}
}

func artifactHasExactGaps(artifact domain.KernelXIDArtifact, expected ...domain.KernelXIDArtifactGap) bool {
	actual := artifact.Gaps()
	if len(actual) != len(expected) {
		return false
	}
	for _, gap := range expected {
		if !artifact.HasGap(gap) {
			return false
		}
	}
	return true
}

// Read uses PostgreSQL's clock as the only expiry authority. It refuses expired
// content and clears its bytes before returning a lifecycle gap.
func (store *KernelXIDArtifactStore) Read(ctx context.Context, scope KernelXIDArtifactScope) (KernelXIDArtifactRead, error) {
	if err := scope.validate(); err != nil {
		return KernelXIDArtifactRead{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return KernelXIDArtifactRead{}, fmt.Errorf("begin kernel XID artifact read: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE kernel_xid_artifacts SET state='EXPIRED', artifact_bytes=NULL WHERE cluster_id=$1 AND run_id=$2 AND work_id=$3 AND attempt=$4 AND target=$5 AND state='AVAILABLE' AND expires_at <= clock_timestamp()`, scope.ClusterID, scope.RunID, scope.WorkID, scope.Attempt, scope.Target); err != nil {
		return KernelXIDArtifactRead{}, fmt.Errorf("expire kernel XID artifact: %w", err)
	}
	result, err := store.readLocked(ctx, tx, scope)
	if err != nil {
		return KernelXIDArtifactRead{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return KernelXIDArtifactRead{}, fmt.Errorf("commit kernel XID artifact read: %w", err)
	}
	return result, nil
}

// ExpireDue clears due AVAILABLE payloads without reading their contents. It
// is intentionally not wired to a runtime scheduler in this repository slice.
func (store *KernelXIDArtifactStore) ExpireDue(ctx context.Context, limit int) (int, error) {
	return store.expireDue(ctx, `clock_timestamp()`, nil, limit)
}

//lint:ignore U1000 exercised by the isolated integration test with a synthetic database clock
func (store *KernelXIDArtifactStore) expireDueAt(ctx context.Context, dbNow time.Time, limit int) (int, error) {
	if dbNow.IsZero() {
		return 0, fmt.Errorf("kernel XID artifact expiry time is required")
	}
	return store.expireDue(ctx, `$1`, []any{dbNow.UTC()}, limit)
}

func (store *KernelXIDArtifactStore) expireDue(ctx context.Context, nowSQL string, args []any, limit int) (int, error) {
	if limit < 1 || limit > 10_000 {
		return 0, fmt.Errorf("kernel XID artifact expiry limit is invalid")
	}
	args = append(args, limit)
	query := `WITH due AS (
		SELECT ctid FROM kernel_xid_artifacts WHERE state='AVAILABLE' AND expires_at <= ` + nowSQL + `
		ORDER BY expires_at, work_id, attempt, target LIMIT $` + fmt.Sprint(len(args)) + ` FOR UPDATE SKIP LOCKED
	) UPDATE kernel_xid_artifacts a SET state='EXPIRED', artifact_bytes=NULL FROM due WHERE a.ctid=due.ctid`
	command, err := store.pool.Exec(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("expire due kernel XID artifacts: %w", err)
	}
	return int(command.RowsAffected()), nil
}

// Delete makes the content unreadable while preserving the scope and an
// explicit DELETED state. It is idempotent for an already-deleted artifact.
func (store *KernelXIDArtifactStore) Delete(ctx context.Context, scope KernelXIDArtifactScope) (bool, error) {
	if err := scope.validate(); err != nil {
		return false, err
	}
	command, err := store.pool.Exec(ctx, `UPDATE kernel_xid_artifacts SET state='DELETED', artifact_bytes=NULL WHERE cluster_id=$1 AND run_id=$2 AND work_id=$3 AND attempt=$4 AND target=$5 AND state='AVAILABLE'`, scope.ClusterID, scope.RunID, scope.WorkID, scope.Attempt, scope.Target)
	if err != nil {
		return false, fmt.Errorf("delete kernel XID artifact: %w", err)
	}
	if command.RowsAffected() == 1 {
		return true, nil
	}
	var state string
	err = store.pool.QueryRow(ctx, `SELECT state FROM kernel_xid_artifacts WHERE cluster_id=$1 AND run_id=$2 AND work_id=$3 AND attempt=$4 AND target=$5`, scope.ClusterID, scope.RunID, scope.WorkID, scope.Attempt, scope.Target).Scan(&state)
	if err == pgx.ErrNoRows {
		return false, application.ErrKernelXIDArtifactNotFound
	}
	if err != nil {
		return false, fmt.Errorf("load kernel XID artifact deletion: %w", err)
	}
	if state == string(KernelXIDArtifactDeleted) {
		return false, nil
	}
	return false, application.ErrKernelXIDArtifactConflict
}

func (store *KernelXIDArtifactStore) readLocked(ctx context.Context, tx pgx.Tx, scope KernelXIDArtifactScope) (KernelXIDArtifactRead, error) {
	var state KernelXIDArtifactState
	var checksum, payload, definitionDigest, sourceDigest []byte
	var binding domain.KernelXIDArtifactBinding
	var schemaVersion, parserVersion, redactionVersion string
	var eventCount int
	var truncated bool
	err := tx.QueryRow(ctx, `SELECT state, cluster_id, run_id, work_id, attempt, target, pack_id, pack_version, definition_id, definition_version, definition_digest, source_stdout_sha256, artifact_schema_version, parser_version, redaction_version, artifact_sha256, artifact_bytes, event_count, truncated FROM kernel_xid_artifacts WHERE cluster_id=$1 AND run_id=$2 AND work_id=$3 AND attempt=$4 AND target=$5 FOR UPDATE`, scope.ClusterID, scope.RunID, scope.WorkID, scope.Attempt, scope.Target).
		Scan(&state, &binding.ClusterID, &binding.RunID, &binding.WorkID, &binding.Attempt, &binding.Target, &binding.PackID, &binding.PackVersion, &binding.DefinitionID, &binding.DefinitionVersion, &definitionDigest, &sourceDigest, &schemaVersion, &parserVersion, &redactionVersion, &checksum, &payload, &eventCount, &truncated)
	if err == pgx.ErrNoRows {
		return KernelXIDArtifactRead{State: KernelXIDArtifactMissing, Gaps: []domain.KernelXIDArtifactGap{domain.KernelXIDArtifactGapMissing}}, nil
	}
	if err != nil {
		return KernelXIDArtifactRead{}, fmt.Errorf("load kernel XID artifact: %w", err)
	}
	switch state {
	case KernelXIDArtifactExpired:
		return KernelXIDArtifactRead{State: state, Gaps: []domain.KernelXIDArtifactGap{domain.KernelXIDArtifactGapExpired}}, nil
	case KernelXIDArtifactDeleted:
		return KernelXIDArtifactRead{State: state, Gaps: []domain.KernelXIDArtifactGap{domain.KernelXIDArtifactGapDeleted}}, nil
	case KernelXIDArtifactCorrupt:
		return KernelXIDArtifactRead{State: state, Gaps: []domain.KernelXIDArtifactGap{domain.KernelXIDArtifactGapCorrupt}}, nil
	case KernelXIDArtifactAvailable:
	default:
		return KernelXIDArtifactRead{State: KernelXIDArtifactCorrupt, Gaps: []domain.KernelXIDArtifactGap{domain.KernelXIDArtifactGapCorrupt}}, nil
	}
	payloadChecksum := domain.ChecksumSHA256(payload)
	if len(checksum) != 32 || !subtleBytesEqual(payloadChecksum[:], checksum) {
		return store.markCorrupt(ctx, tx, scope, domain.KernelXIDArtifactGapChecksumMismatch)
	}
	artifact, err := domain.ParseKernelXIDArtifact(payload)
	if err != nil {
		return store.markCorrupt(ctx, tx, scope, domain.KernelXIDArtifactGapCorrupt)
	}
	if len(definitionDigest) != 32 || len(sourceDigest) != 32 {
		return store.markCorrupt(ctx, tx, scope, domain.KernelXIDArtifactGapBindingMismatch)
	}
	copy(binding.DefinitionDigest[:], definitionDigest)
	copy(binding.SourceStdoutSHA256[:], sourceDigest)
	actual, ok := artifact.Binding()
	if !ok || !domain.KernelXIDArtifactBindingsEqual(actual, binding) || binding.ClusterID != scope.ClusterID || binding.RunID != scope.RunID || binding.WorkID != scope.WorkID || binding.Attempt != scope.Attempt || binding.Target != scope.Target || schemaVersion != domain.KernelXIDArtifactSchemaVersion || parserVersion != domain.KernelXIDArtifactParserVersion || redactionVersion != domain.KernelXIDArtifactRedactionVersion || eventCount != artifact.EventCount() || truncated != artifact.Truncated() {
		return store.markCorrupt(ctx, tx, scope, domain.KernelXIDArtifactGapBindingMismatch)
	}
	return KernelXIDArtifactRead{State: KernelXIDArtifactAvailable, Artifact: &artifact}, nil
}

func (store *KernelXIDArtifactStore) markCorrupt(ctx context.Context, tx pgx.Tx, scope KernelXIDArtifactScope, gap domain.KernelXIDArtifactGap) (KernelXIDArtifactRead, error) {
	if _, err := tx.Exec(ctx, `UPDATE kernel_xid_artifacts SET state='CORRUPT', artifact_bytes=NULL WHERE cluster_id=$1 AND run_id=$2 AND work_id=$3 AND attempt=$4 AND target=$5 AND state='AVAILABLE'`, scope.ClusterID, scope.RunID, scope.WorkID, scope.Attempt, scope.Target); err != nil {
		return KernelXIDArtifactRead{}, fmt.Errorf("mark kernel XID artifact corrupt: %w", err)
	}
	return KernelXIDArtifactRead{State: KernelXIDArtifactCorrupt, Gaps: []domain.KernelXIDArtifactGap{gap}}, nil
}
