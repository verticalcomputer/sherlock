package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// EvidenceStore persists immutable evidence metadata separately from raw
// artifacts. Artifact promotion is reflected by the only permitted metadata
// transition: PENDING to AVAILABLE.
type EvidenceStore struct {
	pool *pgxpool.Pool
}

func NewEvidenceStore(pool *pgxpool.Pool) (*EvidenceStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("PostgreSQL pool is required")
	}
	return &EvidenceStore{pool: pool}, nil
}

func (store *EvidenceStore) CreateEvidence(ctx context.Context, envelope domain.EvidenceEnvelope) (bool, error) {
	created, err := insertEvidenceEnvelope(ctx, store.pool, envelope)
	if err != nil {
		return false, err
	}
	if created {
		return true, nil
	}
	prior, _, found, err := store.LoadEvidence(ctx, envelope.ID())
	if err != nil {
		return false, err
	}
	if !found || !prior.Equal(envelope) {
		return false, application.ErrEvidenceConflict
	}
	return false, nil
}

type evidenceCommandExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func insertEvidenceEnvelope(ctx context.Context, executor evidenceCommandExecutor, envelope domain.EvidenceEnvelope) (bool, error) {
	if err := envelope.Validate(); err != nil {
		return false, fmt.Errorf("validate evidence: %w", err)
	}
	expected, err := json.Marshal(envelope.Coverage().Expected)
	if err != nil {
		return false, fmt.Errorf("encode expected evidence coverage: %w", err)
	}
	covered, err := json.Marshal(envelope.Coverage().Covered)
	if err != nil {
		return false, fmt.Errorf("encode covered evidence coverage: %w", err)
	}
	artifact, hasArtifact := envelope.Artifact()
	var artifactID any
	var checksum any
	var artifactBytes any
	var mediaType any
	var compression any
	var parserVersion any
	var redactionPolicy any
	var redactionMatches any
	var retentionClass any
	availability := "NONE"
	if hasArtifact {
		artifactID = artifact.ArtifactID
		checksum = artifact.SHA256[:]
		artifactBytes = artifact.Bytes
		mediaType = artifact.MediaType
		compression = artifact.Compression
		parserVersion = artifact.ParserVersion
		redactionPolicy = artifact.Redactions.PolicyVersion
		redactionMatches = artifact.Redactions.MatchCount
		retentionClass = artifact.RetentionClass
		availability = string(domain.ArtifactPending)
	}
	var supersedes any
	if value, ok := envelope.Supersedes(); ok {
		supersedes = value
	}
	source := envelope.Source()
	timeRange := envelope.TimeRange()
	command, err := executor.Exec(ctx, `
		INSERT INTO evidence_envelopes (
			evidence_id, schema_version, cluster_id, status, source_id, run_id,
			operation, definition_version, source_reference, observed_start,
			observed_end, collected_at, coverage_expected, coverage_covered,
			artifact_id, artifact_sha256, artifact_bytes, artifact_media_type,
			artifact_compression, artifact_parser_version, redaction_policy_version,
			redaction_match_count, retention_class, artifact_availability,
			supersedes_evidence_id, diagnostic_run_id
		) VALUES (
			$1,$2,$3,$4,$5,NULLIF($6,''),$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
			$17,$18,$19,$20,$21,$22,$23,$24,$25,NULLIF($26,'')
		) ON CONFLICT (evidence_id) DO NOTHING`,
		envelope.ID(), envelope.SchemaVersion(), envelope.ClusterID(), envelope.Status(),
		source.SourceID, source.RunID, source.Operation, source.DefinitionVersion,
		source.Reference, timeRange.Start.UTC(), timeRange.End.UTC(), envelope.CollectedAt().UTC(),
		expected, covered, artifactID, checksum, artifactBytes, mediaType, compression,
		parserVersion, redactionPolicy, redactionMatches, retentionClass, availability, supersedes, source.DiagnosticRunID)
	if err != nil {
		return false, fmt.Errorf("insert evidence %s: %w", envelope.ID(), err)
	}
	return command.RowsAffected() == 1, nil
}

func (store *EvidenceStore) MarkArtifactAvailable(ctx context.Context, evidenceID domain.EvidenceID, artifactID domain.ArtifactID) error {
	if evidenceID == "" || artifactID == "" {
		return fmt.Errorf("evidence and artifact identifiers are required")
	}
	command, err := store.pool.Exec(ctx, `
		UPDATE evidence_envelopes SET artifact_availability='AVAILABLE'
		WHERE evidence_id=$1 AND artifact_id=$2
		  AND artifact_availability IN ('PENDING','AVAILABLE')`, evidenceID, artifactID)
	if err != nil {
		return fmt.Errorf("mark evidence artifact available: %w", err)
	}
	if command.RowsAffected() != 1 {
		return application.ErrArtifactConflict
	}
	return nil
}

func (store *EvidenceStore) ListArtifactReconciliationCandidates(ctx context.Context, createdBefore time.Time, limit int) ([]application.ArtifactReconciliationCandidate, error) {
	if createdBefore.IsZero() || limit < 1 || limit > 10_000 {
		return nil, fmt.Errorf("artifact reconciliation query bounds are invalid")
	}
	rows, err := store.pool.Query(ctx, `
		SELECT evidence_id, artifact_id, artifact_sha256, artifact_bytes,
		       artifact_media_type, artifact_compression, artifact_parser_version,
		       redaction_policy_version, redaction_match_count, retention_class,
		       artifact_availability
		FROM evidence_envelopes
		WHERE artifact_id IS NOT NULL AND created_at <= $1
		ORDER BY artifact_checked_at NULLS FIRST, created_at, evidence_id
		LIMIT $2`, createdBefore.UTC(), limit)
	if err != nil {
		return nil, fmt.Errorf("query artifact reconciliation candidates: %w", err)
	}
	defer rows.Close()
	var candidates []application.ArtifactReconciliationCandidate
	for rows.Next() {
		var candidate application.ArtifactReconciliationCandidate
		var checksum []byte
		if err := rows.Scan(&candidate.EvidenceID, &candidate.Reference.ArtifactID, &checksum,
			&candidate.Reference.Bytes, &candidate.Reference.MediaType, &candidate.Reference.Compression,
			&candidate.Reference.ParserVersion, &candidate.Reference.Redactions.PolicyVersion,
			&candidate.Reference.Redactions.MatchCount, &candidate.Reference.RetentionClass,
			&candidate.Condition); err != nil {
			return nil, fmt.Errorf("scan artifact reconciliation candidate: %w", err)
		}
		if len(checksum) != len(candidate.Reference.SHA256) {
			return nil, fmt.Errorf("stored artifact checksum length is invalid")
		}
		copy(candidate.Reference.SHA256[:], checksum)
		if err := domain.ValidateArtifactReference(candidate.Reference); err != nil {
			return nil, fmt.Errorf("validate artifact reconciliation candidate: %w", err)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate artifact reconciliation candidates: %w", err)
	}
	return candidates, nil
}

func (store *EvidenceStore) SetArtifactAvailability(ctx context.Context, evidenceID domain.EvidenceID, artifactID domain.ArtifactID, condition domain.ArtifactAvailability) error {
	if evidenceID == "" || artifactID == "" {
		return fmt.Errorf("evidence and artifact identifiers are required")
	}
	if condition != domain.ArtifactAvailable && condition != domain.ArtifactUnavailable && condition != domain.ArtifactCorrupt {
		return fmt.Errorf("invalid reconciled artifact condition %q", condition)
	}
	command, err := store.pool.Exec(ctx, `UPDATE evidence_envelopes SET artifact_availability=$3, artifact_checked_at=clock_timestamp() WHERE evidence_id=$1 AND artifact_id=$2`, evidenceID, artifactID, condition)
	if err != nil {
		return fmt.Errorf("set evidence artifact availability: %w", err)
	}
	if command.RowsAffected() != 1 {
		return application.ErrArtifactConflict
	}
	return nil
}

func (store *EvidenceStore) ArtifactAvailability(ctx context.Context, evidenceID domain.EvidenceID) (domain.EvidenceArtifactAvailability, bool, error) {
	if evidenceID == "" {
		return domain.EvidenceArtifactAvailability{}, false, fmt.Errorf("evidence identifier is required")
	}
	var artifactID domain.ArtifactID
	var condition domain.ArtifactAvailability
	err := store.pool.QueryRow(ctx, `
		SELECT artifact_id, artifact_availability
		FROM evidence_envelopes WHERE evidence_id=$1 AND artifact_id IS NOT NULL`, evidenceID).
		Scan(&artifactID, &condition)
	if err == pgx.ErrNoRows {
		return domain.EvidenceArtifactAvailability{}, false, nil
	}
	if err != nil {
		return domain.EvidenceArtifactAvailability{}, false, fmt.Errorf("read evidence artifact availability: %w", err)
	}
	availability := domain.EvidenceArtifactAvailability{EvidenceID: evidenceID, ArtifactID: artifactID, Condition: condition}
	if err := availability.Validate(); err != nil {
		return domain.EvidenceArtifactAvailability{}, false, fmt.Errorf("validate stored artifact availability: %w", err)
	}
	return availability, true, nil
}

// LoadEvidence reconstructs the immutable envelope and separately returns its
// mutable artifact availability condition.
func (store *EvidenceStore) LoadEvidence(ctx context.Context, evidenceID domain.EvidenceID) (domain.EvidenceEnvelope, domain.ArtifactAvailability, bool, error) {
	var schemaVersion int
	var clusterID domain.ClusterID
	var status domain.EvidenceStatus
	var source domain.EvidenceSourceReference
	var timeRange domain.EvidenceTimeRange
	var collectedAt time.Time
	var expectedJSON, coveredJSON []byte
	var artifactID *string
	var checksum []byte
	var artifactBytes *int64
	var mediaType, compression, parserVersion, redactionPolicy, retentionClass *string
	var redactionMatches *int
	var availability domain.ArtifactAvailability
	var supersedes *string
	err := store.pool.QueryRow(ctx, `
		SELECT schema_version, cluster_id, status, source_id, COALESCE(run_id,''),
		       operation, definition_version, source_reference, observed_start,
		       observed_end, collected_at, coverage_expected, coverage_covered,
		       artifact_id, artifact_sha256, artifact_bytes, artifact_media_type,
		       artifact_compression, artifact_parser_version, redaction_policy_version,
		       redaction_match_count, retention_class, artifact_availability,
		       supersedes_evidence_id, COALESCE(diagnostic_run_id,'')
		FROM evidence_envelopes WHERE evidence_id=$1`, evidenceID).Scan(
		&schemaVersion, &clusterID, &status, &source.SourceID, &source.RunID,
		&source.Operation, &source.DefinitionVersion, &source.Reference,
		&timeRange.Start, &timeRange.End, &collectedAt, &expectedJSON, &coveredJSON,
		&artifactID, &checksum, &artifactBytes, &mediaType, &compression, &parserVersion,
		&redactionPolicy, &redactionMatches, &retentionClass, &availability, &supersedes, &source.DiagnosticRunID)
	if err == pgx.ErrNoRows {
		return domain.EvidenceEnvelope{}, "", false, nil
	}
	if err != nil {
		return domain.EvidenceEnvelope{}, "", false, fmt.Errorf("load evidence %s: %w", evidenceID, err)
	}
	var coverage domain.EvidenceCoverage
	if err := json.Unmarshal(expectedJSON, &coverage.Expected); err != nil {
		return domain.EvidenceEnvelope{}, "", false, fmt.Errorf("decode expected evidence coverage: %w", err)
	}
	if err := json.Unmarshal(coveredJSON, &coverage.Covered); err != nil {
		return domain.EvidenceEnvelope{}, "", false, fmt.Errorf("decode covered evidence coverage: %w", err)
	}
	var artifact *domain.ArtifactReference
	if artifactID != nil {
		if len(checksum) != 32 || artifactBytes == nil || mediaType == nil || compression == nil || parserVersion == nil || redactionPolicy == nil || redactionMatches == nil || retentionClass == nil {
			return domain.EvidenceEnvelope{}, "", false, fmt.Errorf("stored artifact metadata is incomplete")
		}
		var sha domain.SHA256
		copy(sha[:], checksum)
		value := domain.ArtifactReference{
			ArtifactID: domain.ArtifactID(*artifactID), SHA256: sha, Bytes: *artifactBytes,
			MediaType: *mediaType, Compression: domain.ArtifactCompression(*compression),
			ParserVersion:  *parserVersion,
			Redactions:     domain.RedactionSummary{PolicyVersion: *redactionPolicy, MatchCount: *redactionMatches},
			RetentionClass: domain.ArtifactRetentionClass(*retentionClass),
		}
		artifact = &value
	}
	var supersedesID *domain.EvidenceID
	if supersedes != nil {
		value := domain.EvidenceID(*supersedes)
		supersedesID = &value
	}
	envelope, err := domain.CreateEvidenceEnvelope(domain.NewEvidenceEnvelope{
		ID: evidenceID, SchemaVersion: schemaVersion, ClusterID: clusterID, Status: status,
		Source: source, TimeRange: timeRange, CollectedAt: collectedAt,
		Coverage: coverage, Artifact: artifact, Supersedes: supersedesID,
	})
	if err != nil {
		return domain.EvidenceEnvelope{}, "", false, fmt.Errorf("reconstruct evidence %s: %w", evidenceID, err)
	}
	return envelope, availability, true, nil
}

// EnsureDiagnosticSource creates the synthetic source a projected diagnostic
// envelope refers to.
//
// A diagnostic's source is the reviewed command pack, not a polled system, so
// no collector ever provisions it. Without this the first completed diagnostic
// fails on evidence_envelopes' foreign key and the execution is lost after the
// work was already done. Creation is guarded on the cluster existing and is
// idempotent, matching how model-payload evidence provisions its own source.
func (store *EvidenceStore) EnsureDiagnosticSource(ctx context.Context, clusterID domain.ClusterID, sourceID domain.SourceID) error {
	if clusterID == "" || sourceID == "" {
		return fmt.Errorf("diagnostic evidence source identity is required")
	}
	command, err := store.pool.Exec(ctx, `INSERT INTO sources (source_id,cluster_id,kind,display_name) SELECT $1,$2,'diagnostic','Diagnostic execution' FROM clusters WHERE cluster_id=$2 ON CONFLICT (source_id) DO NOTHING`, sourceID, clusterID)
	if err != nil {
		return fmt.Errorf("ensure diagnostic evidence source: %w", err)
	}
	if command.RowsAffected() == 1 {
		return nil
	}
	var storedCluster domain.ClusterID
	var kind string
	if err := store.pool.QueryRow(ctx, `SELECT cluster_id,kind FROM sources WHERE source_id=$1`, sourceID).Scan(&storedCluster, &kind); err != nil {
		return fmt.Errorf("load diagnostic evidence source: %w", err)
	}
	if storedCluster != clusterID || kind != "diagnostic" {
		return fmt.Errorf("diagnostic evidence source attribution conflict")
	}
	return nil
}
