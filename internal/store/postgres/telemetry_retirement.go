package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

// A final cloud ownership receipt does not prove node compaction. Only a
// separately signed completion advances the node prefix/session retirement.
type telemetryReleaseRow struct {
	request    telemetry.ReleaseRequest
	manifest   telemetry.ReleaseManifest
	admission  telemetry.ReleaseAdmissionReceipt
	prepared   telemetry.CloudRetirementReceipt
	commit     *telemetry.GatewayReleaseCommit
	final      *telemetry.CloudRetirementReceipt
	completion *telemetry.NodeReleaseCompletion
	receipt    *telemetry.NodeCompletionReceipt
}
type telemetryReleaseSession struct {
	terminal                     *string
	released, completed, expired uint64
	empty                        bool
}

func withTelemetryRetirement[T any](ctx context.Context, s *TelemetryStore, fn func(context.Context, pgx.Tx) (T, error)) (out T, err error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = retryTelemetryTransaction(ctx, func() error {
		tx, e := beginTelemetryTx(ctx, s.pool)
		if e != nil {
			return e
		}
		defer rollbackMonitoringTx(tx)
		value, e := fn(ctx, tx)
		if e != nil {
			return e
		}
		if e = tx.Commit(ctx); e != nil {
			return e
		}
		out = value
		return nil
	})
	if err != nil {
		var zero T
		out = zero
	}
	return out, telemetrySafeError(err)
}
func retirementAuthority(ctx context.Context, tx pgx.Tx, cluster domain.ClusterID, collector domain.CollectorID, id string) (telemetry.Grant, time.Time, error) {
	var at time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return telemetry.Grant{}, at, err
	}
	grant, err := loadTelemetryGrant(ctx, tx, cluster, collector, id, at, true)
	if err != nil {
		return grant, at, err
	}
	// Authority may have waited for an inventory writer. Validate signing/future
	// times against a fresh database clock after that authoritative lock boundary.
	err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at)
	// pgx may return time.Local even when its offset is UTC. JSON decodes a
	// zero-offset receipt as time.UTC, so issue the same representation that
	// immutable receipt replay returns without changing the timestamp instant.
	at = at.UTC()
	grant.NotBefore = at
	grant.NotAfter = at.Add(telemetry.GrantLease)
	return grant, at, err
}
func loadReleaseSession(ctx context.Context, tx pgx.Tx, b telemetry.ReleaseBinding) (out telemetryReleaseSession, err error) {
	var released, completed, expired string
	err = tx.QueryRow(ctx, `SELECT last_allocated_sequence::text,released_through::text,node_completed_through::text,retirement_receipts_expired_through::text,empty_release_completed FROM gp06f_telemetry_sessions WHERE enrollment_id=$1 AND session_epoch=$2 AND session_id=$3`, b.EnrollmentID, b.SessionEpoch, b.SessionID).Scan(&out.terminal, &released, &completed, &expired, &out.empty)
	if err != nil {
		return out, err
	}
	out.released, err = telemetryU64(released)
	if err != nil {
		return out, err
	}
	out.completed, err = telemetryU64(completed)
	if err != nil {
		return out, err
	}
	out.expired, err = telemetryU64(expired)
	return out, err
}
func loadReleaseRow(ctx context.Context, tx pgx.Tx, id, release string) (out telemetryReleaseRow, err error) {
	var request, manifest, admission, prepared, commit, final, completion, receipt []byte
	err = tx.QueryRow(ctx, `SELECT request,manifest,admission,prepared_receipt,gateway_commit,final_receipt,node_completion,completion_receipt FROM gp06f_telemetry_retirements WHERE enrollment_id=$1 AND release_id=$2`, id, release).Scan(&request, &manifest, &admission, &prepared, &commit, &final, &completion, &receipt)
	if err != nil {
		return out, err
	}
	for _, p := range []struct {
		body   []byte
		target any
	}{{request, &out.request}, {manifest, &out.manifest}, {admission, &out.admission}, {prepared, &out.prepared}} {
		if err = json.Unmarshal(p.body, p.target); err != nil {
			return out, err
		}
	}
	if len(commit) > 0 {
		out.commit = new(telemetry.GatewayReleaseCommit)
		if err = json.Unmarshal(commit, out.commit); err != nil {
			return out, err
		}
	}
	if len(final) > 0 {
		out.final = new(telemetry.CloudRetirementReceipt)
		if err = json.Unmarshal(final, out.final); err != nil {
			return out, err
		}
	}
	if len(completion) > 0 {
		out.completion = new(telemetry.NodeReleaseCompletion)
		if err = json.Unmarshal(completion, out.completion); err != nil {
			return out, err
		}
	}
	if len(receipt) > 0 {
		out.receipt = new(telemetry.NodeCompletionReceipt)
		if err = json.Unmarshal(receipt, out.receipt); err != nil {
			return out, err
		}
	}
	return out, nil
}
func retirementExpired(b telemetry.ReleaseBinding, state telemetryReleaseSession) bool {
	last, e := telemetryU64(b.ThroughSequence)
	return e == nil && last > 0 && last <= state.expired
}
func sameReleaseRequest(a, b telemetry.ReleaseRequest) bool {
	return a.Binding() == b.Binding() && a.SigningKeyID == b.SigningKeyID && a.CreatedAt.Equal(b.CreatedAt) && a.Signature == b.Signature
}
func sameAdmission(a, b telemetry.ReleaseAdmissionReceipt) bool {
	return a.ProtocolVersion == b.ProtocolVersion && a.ReleaseVersion == b.ReleaseVersion && a.ID == b.ID && a.Binding == b.Binding && a.StoredAt.Equal(b.StoredAt) && a.Durability == b.Durability
}
func sameReleaseCommit(a, b telemetry.GatewayReleaseCommit) bool {
	return a.ProtocolVersion == b.ProtocolVersion && a.ReleaseVersion == b.ReleaseVersion && a.ID == b.ID && a.Binding == b.Binding && a.GatewayAdmissionID == b.GatewayAdmissionID && a.PreparedReceiptID == b.PreparedReceiptID && a.CreatedAt.Equal(b.CreatedAt)
}

func (s *TelemetryStore) PrepareRetirement(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, request telemetry.ReleaseRequest, manifest telemetry.ReleaseManifest, admission telemetry.ReleaseAdmissionReceipt) (telemetry.CloudRetirementReceipt, error) {
	if telemetry.ValidateReleaseEnvelope(telemetry.ReleaseEnvelope{Request: request, Manifest: manifest}) != nil || telemetry.ValidateReleaseAdmissionReceipt(admission) != nil || admission.Binding != request.Binding() {
		return telemetry.CloudRetirementReceipt{}, telemetry.ErrInvalid
	}
	return withTelemetryRetirement(ctx, s, func(ctx context.Context, tx pgx.Tx) (out telemetry.CloudRetirementReceipt, err error) {
		grant, at, err := retirementAuthority(ctx, tx, cluster, collector, request.EnrollmentID)
		if err != nil {
			return out, err
		}
		if err = telemetry.ValidateReleaseForGrant(request, grant, at); err != nil {
			return out, err
		}
		if admission.StoredAt.After(at.Add(telemetry.FutureSkew)) {
			return out, telemetry.ErrInvalid
		}
		state, err := loadReleaseSession(ctx, tx, request.Binding())
		if err != nil {
			return out, err
		}
		row, err := loadReleaseRow(ctx, tx, grant.EnrollmentID, request.ReleaseID)
		if err == nil {
			if !sameReleaseRequest(row.request, request) || !sameAdmission(row.admission, admission) {
				return out, telemetry.ErrConflict
			}
			return row.prepared, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return out, err
		}
		if retirementExpired(request.Binding(), state) {
			return out, telemetry.ErrReplayExpired
		}
		key, _, err := telemetrySigningKey(grant, request.SigningKeyID)
		if err != nil || key.State != "ACTIVE" {
			return out, telemetry.ErrUnauthorized
		}
		first, _ := telemetryU64(request.FromSequence)
		last, _ := telemetryU64(request.ThroughSequence)
		if first == 0 {
			if state.terminal == nil || *state.terminal != "0" || state.empty {
				return out, telemetry.ErrConflict
			}
		} else if state.released == ^uint64(0) || first != state.released+1 {
			return out, telemetry.ErrConflict
		}
		if state.terminal != nil {
			end, e := telemetryU64(*state.terminal)
			if e != nil {
				return out, e
			}
			if last > end {
				return out, telemetry.ErrConflict
			}
		}
		var pending int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM gp06f_telemetry_retirements WHERE enrollment_id=$1 AND session_epoch=$2 AND completed_at IS NULL`, grant.EnrollmentID, request.SessionEpoch).Scan(&pending); err != nil {
			return out, err
		}
		if pending != 0 {
			return out, telemetry.ErrBackpressure
		}
		losses, err := verifyRetirementManifest(ctx, tx, grant, request, manifest)
		if err != nil {
			return out, err
		}
		sources := make([]string, 0, len(grant.Sources))
		for _, source := range grant.Sources {
			sources = append(sources, source.SourceID)
		}
		if err = telemetry.ProveReleaseCoverage(request, manifest, sources, losses); err != nil {
			return out, err
		}
		if err = reserveReleaseReceipt(ctx, tx, grant.EnrollmentID, request.SessionEpoch); err != nil {
			return out, err
		}
		out = telemetry.CloudRetirementReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: telemetryReceiptID("RELEASE_PREPARED", grant.EnrollmentID, request.SessionEpoch, request.ReleaseID, request.Digest), Phase: "PREPARED", Binding: request.Binding(), GatewayAdmissionID: admission.ID, StoredAt: at, Durability: "CLOUD"}
		requestBody, _ := json.Marshal(request)
		manifestBody, _ := json.Marshal(manifest)
		admissionBody, _ := json.Marshal(admission)
		receiptBody, _ := json.Marshal(out)
		_, err = tx.Exec(ctx, `INSERT INTO gp06f_telemetry_retirements(enrollment_id,release_id,session_epoch,session_id,signing_key_id,from_sequence,through_sequence,release_digest,manifest_digest,request,manifest,gateway_admission_id,admission,prepared_receipt_id,prepared_receipt,prepared_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, grant.EnrollmentID, request.ReleaseID, request.SessionEpoch, request.SessionID, request.SigningKeyID, request.FromSequence, request.ThroughSequence, request.Digest, request.ManifestDigest, requestBody, manifestBody, admission.ID, admissionBody, out.ID, receiptBody, at)
		return out, err
	})
}
func verifyRetirementManifest(ctx context.Context, tx pgx.Tx, grant telemetry.Grant, request telemetry.ReleaseRequest, manifest telemetry.ReleaseManifest) ([]telemetry.SessionLoss, error) {
	if len(manifest.Batches) > 0 {
		sequences := make([]string, 0, len(manifest.Batches))
		expected := map[string]telemetry.ReleaseBatchFact{}
		for _, fact := range manifest.Batches {
			sequences = append(sequences, fact.Sequence)
			expected[fact.Sequence] = fact
		}
		rows, err := tx.Query(ctx, `SELECT sequence::text,digest,gateway_receipt_id FROM gp06f_telemetry_batches WHERE enrollment_id=$1 AND session_epoch=$2 AND sequence IN(SELECT value::numeric FROM unnest($3::text[]) value) LIMIT 257`, grant.EnrollmentID, request.SessionEpoch, sequences)
		if err != nil {
			return nil, err
		}
		count := 0
		for rows.Next() {
			var fact telemetry.ReleaseBatchFact
			if err = rows.Scan(&fact.Sequence, &fact.Digest, &fact.GatewayReceiptID); err != nil {
				rows.Close()
				return nil, err
			}
			if fact != expected[fact.Sequence] {
				rows.Close()
				return nil, telemetry.ErrConflict
			}
			count++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		if count != len(expected) {
			return nil, telemetry.ErrConflict
		}
	}
	losses := make([]telemetry.SessionLoss, 0, len(manifest.Loss))
	if len(manifest.Loss) == 0 {
		return losses, nil
	}
	ids := make([]string, 0, len(manifest.Loss))
	expected := map[string]bool{}
	for _, ref := range manifest.Loss {
		ids = append(ids, ref.LossID)
		expected[ref.SourceID+"\x00"+ref.LossID] = true
	}
	rows, err := tx.Query(ctx, `SELECT source_id,fact FROM gp06f_telemetry_loss WHERE enrollment_id=$1 AND session_epoch=$2 AND loss_id=ANY($3::text[]) LIMIT 257`, grant.EnrollmentID, request.SessionEpoch, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var loss telemetry.SessionLoss
		var body []byte
		if err = rows.Scan(&loss.SourceID, &body); err != nil {
			rows.Close()
			return nil, err
		}
		if err = json.Unmarshal(body, &loss.Range); err != nil {
			rows.Close()
			return nil, err
		}
		if !expected[loss.SourceID+"\x00"+loss.Range.ID] {
			rows.Close()
			return nil, telemetry.ErrConflict
		}
		losses = append(losses, loss)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(losses) != len(manifest.Loss) {
		return nil, telemetry.ErrConflict
	}
	return losses, nil
}

// Keep at most eight exact retirement records. Only fully node-completed old
// receipts can expire; their committed range becomes an explicit replay fence.
func reserveReleaseReceipt(ctx context.Context, tx pgx.Tx, id, epoch string) error {
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM gp06f_telemetry_retirements WHERE enrollment_id=$1 AND session_epoch=$2`, id, epoch).Scan(&count); err != nil {
		return err
	}
	if count < 8 {
		return nil
	}
	if count > 8 {
		return telemetry.ErrBackpressure
	}
	var release, through string
	err := tx.QueryRow(ctx, `SELECT release_id,through_sequence::text FROM gp06f_telemetry_retirements WHERE enrollment_id=$1 AND session_epoch=$2 AND completed_at IS NOT NULL AND through_sequence>0 ORDER BY through_sequence LIMIT 1`, id, epoch).Scan(&release, &through)
	if errors.Is(err, pgx.ErrNoRows) {
		return telemetry.ErrBackpressure
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE gp06f_telemetry_sessions SET retirement_receipts_expired_through=greatest(retirement_receipts_expired_through,$3::numeric) WHERE enrollment_id=$1 AND session_epoch=$2`, id, epoch, through); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `DELETE FROM gp06f_telemetry_retirements WHERE enrollment_id=$1 AND release_id=$2`, id, release)
	return err
}

func (s *TelemetryStore) CommitRetirement(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, request telemetry.ReleaseRequest, commit telemetry.GatewayReleaseCommit) (telemetry.CloudRetirementReceipt, error) {
	if telemetry.ValidateReleaseRequest(request) != nil || telemetry.ValidateGatewayReleaseCommit(commit) != nil || request.Binding() != commit.Binding {
		return telemetry.CloudRetirementReceipt{}, telemetry.ErrInvalid
	}
	return withTelemetryRetirement(ctx, s, func(ctx context.Context, tx pgx.Tx) (out telemetry.CloudRetirementReceipt, err error) {
		grant, at, err := retirementAuthority(ctx, tx, cluster, collector, request.EnrollmentID)
		if err != nil {
			return out, err
		}
		if err = telemetry.ValidateReleaseForGrant(request, grant, at); err != nil {
			return out, err
		}
		if commit.CreatedAt.After(at.Add(telemetry.FutureSkew)) {
			return out, telemetry.ErrInvalid
		}
		state, err := loadReleaseSession(ctx, tx, request.Binding())
		if err != nil {
			return out, err
		}
		row, err := loadReleaseRow(ctx, tx, grant.EnrollmentID, request.ReleaseID)
		if errors.Is(err, pgx.ErrNoRows) && retirementExpired(request.Binding(), state) {
			return out, telemetry.ErrReplayExpired
		}
		if err != nil {
			return out, err
		}
		if !sameReleaseRequest(row.request, request) || commit.GatewayAdmissionID != row.admission.ID || commit.PreparedReceiptID != row.prepared.ID {
			return out, telemetry.ErrConflict
		}
		if row.final != nil {
			if row.commit == nil || !sameReleaseCommit(*row.commit, commit) {
				return out, telemetry.ErrConflict
			}
			return *row.final, nil
		}
		first, _ := telemetryU64(request.FromSequence)
		if first > 0 && (state.released == ^uint64(0) || first != state.released+1) {
			return out, telemetry.ErrConflict
		}
		out = telemetry.CloudRetirementReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: telemetryReceiptID("RELEASE_FINAL", grant.EnrollmentID, request.SessionEpoch, commit.ID, request.Digest), Phase: "FINAL", Binding: request.Binding(), GatewayAdmissionID: row.admission.ID, PreparedReceiptID: row.prepared.ID, GatewayCommitID: commit.ID, StoredAt: at, Durability: "CLOUD"}
		body, _ := json.Marshal(commit)
		receipt, _ := json.Marshal(out)
		if _, err = tx.Exec(ctx, `UPDATE gp06f_telemetry_retirements SET gateway_commit_id=$3,gateway_commit=$4,final_receipt_id=$5,final_receipt=$6,final_at=$7 WHERE enrollment_id=$1 AND release_id=$2`, grant.EnrollmentID, request.ReleaseID, commit.ID, body, out.ID, receipt, at); err != nil {
			return out, err
		}
		_, err = tx.Exec(ctx, `UPDATE gp06f_telemetry_sessions SET released_through=$3 WHERE enrollment_id=$1 AND session_epoch=$2`, grant.EnrollmentID, request.SessionEpoch, request.ThroughSequence)
		return out, err
	})
}

func (s *TelemetryStore) CompleteRetirement(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, completion telemetry.NodeReleaseCompletion) (telemetry.NodeCompletionReceipt, error) {
	return withTelemetryRetirement(ctx, s, func(ctx context.Context, tx pgx.Tx) (out telemetry.NodeCompletionReceipt, err error) {
		grant, at, err := retirementAuthority(ctx, tx, cluster, collector, completion.Binding.EnrollmentID)
		if err != nil {
			return out, err
		}
		if err = telemetry.ValidateNodeCompletionForGrant(completion, grant, at); err != nil {
			return out, err
		}
		state, err := loadReleaseSession(ctx, tx, completion.Binding)
		if err != nil {
			return out, err
		}
		row, err := loadReleaseRow(ctx, tx, grant.EnrollmentID, completion.Binding.ReleaseID)
		if errors.Is(err, pgx.ErrNoRows) && retirementExpired(completion.Binding, state) {
			return out, telemetry.ErrReplayExpired
		}
		if err != nil {
			return out, err
		}
		if row.request.Binding() != completion.Binding || row.final == nil || row.final.ID != completion.CloudFinalReceiptID {
			return out, telemetry.ErrConflict
		}
		gatewayID, e := telemetry.GatewayRetirementReceiptID(*row.final)
		if e != nil || gatewayID != completion.GatewayRetirementReceiptID {
			return out, telemetry.ErrConflict
		}
		if row.receipt != nil {
			if row.completion == nil || row.completion.ID != completion.ID || row.completion.Digest != completion.Digest || row.completion.Signature != completion.Signature {
				return out, telemetry.ErrConflict
			}
			return *row.receipt, nil
		}
		key, _, err := telemetrySigningKey(grant, completion.SigningKeyID)
		if err != nil || key.State != "ACTIVE" {
			return out, telemetry.ErrUnauthorized
		}
		first, _ := telemetryU64(completion.Binding.FromSequence)
		last, _ := telemetryU64(completion.Binding.ThroughSequence)
		if first > 0 && (state.completed == ^uint64(0) || first != state.completed+1) {
			return out, telemetry.ErrConflict
		}
		out = telemetry.NodeCompletionReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: telemetryReceiptID("RELEASE_NODE_COMPLETED", grant.EnrollmentID, completion.Binding.SessionEpoch, completion.ID, completion.Digest), Binding: completion.Binding, CompletionDigest: completion.Digest, CloudFinalReceiptID: completion.CloudFinalReceiptID, GatewayRetirementReceiptID: completion.GatewayRetirementReceiptID, StoredAt: at, Durability: "CLOUD"}
		body, _ := json.Marshal(completion)
		receipt, _ := json.Marshal(out)
		if _, err = tx.Exec(ctx, `UPDATE gp06f_telemetry_retirements SET node_completion_id=$3,node_completion=$4,completion_receipt_id=$5,completion_receipt=$6,completed_at=$7 WHERE enrollment_id=$1 AND release_id=$2`, grant.EnrollmentID, completion.Binding.ReleaseID, completion.ID, body, out.ID, receipt, at); err != nil {
			return out, err
		}
		if _, err = tx.Exec(ctx, `UPDATE gp06f_telemetry_sessions SET node_completed_through=$3,empty_release_completed=empty_release_completed OR $4,retired_at=CASE WHEN last_allocated_sequence=$3::numeric THEN coalesce(retired_at,$5) ELSE retired_at END WHERE enrollment_id=$1 AND session_epoch=$2`, grant.EnrollmentID, completion.Binding.SessionEpoch, completion.Binding.ThroughSequence, last == 0, at); err != nil {
			return out, err
		}
		if err = advanceRetiredEpoch(ctx, tx, grant.EnrollmentID); err != nil {
			return out, err
		}
		return out, nil
	})
}
func advanceRetiredEpoch(ctx context.Context, tx pgx.Tx, id string) error {
	var text string
	if err := tx.QueryRow(ctx, `SELECT retired_through_epoch::text FROM gp06f_telemetry_enrollments WHERE enrollment_id=$1`, id).Scan(&text); err != nil {
		return err
	}
	base, err := telemetryU64(text)
	if err != nil {
		return err
	}
	for i := 0; i < 8 && base != ^uint64(0); i++ {
		var retired bool
		err = tx.QueryRow(ctx, `SELECT retired_at IS NOT NULL FROM gp06f_telemetry_sessions WHERE enrollment_id=$1 AND session_epoch=$2`, id, strconv.FormatUint(base+1, 10)).Scan(&retired)
		if errors.Is(err, pgx.ErrNoRows) {
			break
		}
		if err != nil {
			return err
		}
		if !retired {
			break
		}
		base++
	}
	_, err = tx.Exec(ctx, `UPDATE gp06f_telemetry_enrollments SET retired_through_epoch=$2 WHERE enrollment_id=$1`, id, strconv.FormatUint(base, 10))
	return err
}

// Missing originals and previously unknown intersecting loss facts cannot enter
// a prepared/final range. Exact existing evidence replay is checked first.
func telemetryRetirementFenced(ctx context.Context, tx pgx.Tx, id, epoch string, first, last uint64) (bool, error) {
	fences, err := loadTelemetryRetirementFences(ctx, tx, id, epoch)
	return telemetryFenceOverlap(fences, first, last), err
}

func loadTelemetryRetirementFences(ctx context.Context, tx pgx.Tx, id, epoch string) ([]telemetryInterval, error) {
	var released string
	var first, last *string
	err := tx.QueryRow(ctx, `SELECT s.released_through::text,r.from_sequence::text,r.through_sequence::text FROM gp06f_telemetry_sessions s LEFT JOIN gp06f_telemetry_retirements r ON r.enrollment_id=s.enrollment_id AND r.session_epoch=s.session_epoch AND r.completed_at IS NULL WHERE s.enrollment_id=$1 AND s.session_epoch=$2`, id, epoch).Scan(&released, &first, &last)
	if err != nil {
		return nil, err
	}
	prefix, err := telemetryU64(released)
	if err != nil {
		return nil, err
	}
	var fences []telemetryInterval
	if prefix > 0 {
		fences = append(fences, telemetryInterval{from: 1, through: prefix})
	}
	if first != nil && last != nil {
		a, err := telemetryU64(*first)
		if err != nil {
			return nil, err
		}
		b, err := telemetryU64(*last)
		if err != nil {
			return nil, err
		}
		fences = append(fences, telemetryInterval{from: a, through: b})
	}
	return fences, nil
}

func telemetryFenceOverlap(fences []telemetryInterval, first, last uint64) bool {
	for _, fence := range fences {
		if first <= fence.through && last >= fence.from {
			return true
		}
	}
	return false
}

func (s *TelemetryStore) RetirementCapabilities(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, id string) (telemetry.RetirementCapabilities, error) {
	return withTelemetryRetirement(ctx, s, func(ctx context.Context, tx pgx.Tx) (telemetry.RetirementCapabilities, error) {
		if _, _, err := retirementAuthority(ctx, tx, cluster, collector, id); err != nil {
			return telemetry.RetirementCapabilities{}, err
		}
		var ready bool
		err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM gp06f_telemetry_retirements WHERE enrollment_id=$1) OR retired_through_epoch>=0 FROM gp06f_telemetry_enrollments WHERE enrollment_id=$1`, id).Scan(&ready)
		if err != nil {
			return telemetry.RetirementCapabilities{}, err
		}
		if !ready {
			return telemetry.RetirementCapabilities{}, telemetry.ErrUnavailable
		}
		return telemetry.SupportedRetirementCapabilities(), nil
	})
}
