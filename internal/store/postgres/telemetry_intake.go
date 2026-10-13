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

func telemetryReceiptID(kind, id, epoch, sequence, digest string) string {
	return "telemetry-" + monitoringDigest(kind, id, epoch, sequence, digest)
}

func (s *TelemetryStore) registerSession(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, message telemetry.SessionMessage) (receipt telemetry.SessionReceipt, err error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := beginTelemetryTx(ctx, s.pool)
	if err != nil {
		return receipt, err
	}
	defer rollbackMonitoringTx(tx)
	var at time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return receipt, err
	}
	grant, err := loadTelemetryGrant(ctx, tx, cluster, collector, message.EnrollmentID, at, true)
	if err != nil {
		return receipt, err
	}
	if err = telemetry.ValidateSessionForGrant(message, grant, at); err != nil {
		return receipt, err
	}
	key, public, err := telemetrySigningKey(grant, message.SigningKeyID)
	if err != nil {
		return receipt, err
	}
	if err = telemetry.VerifySessionSignature(message, public); err != nil {
		return receipt, telemetry.ErrUnauthorized
	}
	var existingDigest string
	var previousReceipt []byte
	err = tx.QueryRow(ctx, `SELECT digest,receipt FROM gp06f_telemetry_lifecycle WHERE enrollment_id=$1 AND session_epoch=$2 AND kind=$3`, grant.EnrollmentID, message.SessionEpoch, message.Kind).Scan(&existingDigest, &previousReceipt)
	if err == nil {
		if existingDigest != message.Digest {
			return receipt, telemetry.ErrConflict
		}
		if err = json.Unmarshal(previousReceipt, &receipt); err != nil {
			return receipt, err
		}
		return receipt, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return receipt, err
	}
	switch message.Kind {
	case "OPEN":
		if key.State != "ACTIVE" {
			return receipt, telemetry.ErrUnauthorized
		}
		var highest string
		if err = tx.QueryRow(ctx, `SELECT highest_epoch::text FROM gp06f_telemetry_enrollments WHERE enrollment_id=$1`, grant.EnrollmentID).Scan(&highest); err != nil {
			return receipt, err
		}
		n, err := telemetryU64(highest)
		if err != nil {
			return receipt, err
		}
		epoch, err := telemetryU64(message.SessionEpoch)
		if err != nil {
			return receipt, err
		}
		if n == ^uint64(0) || epoch != n+1 {
			return receipt, telemetry.ErrConflict
		}
		var active int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM gp06f_telemetry_sessions WHERE enrollment_id=$1 AND retired_at IS NULL`, grant.EnrollmentID).Scan(&active); err != nil {
			return receipt, err
		}
		if active >= 8 {
			return receipt, telemetry.ErrBackpressure
		}
		if _, err = tx.Exec(ctx, `INSERT INTO gp06f_telemetry_sessions(enrollment_id,session_epoch,session_id,boot_id,key_id,opened_at) VALUES($1,$2,$3,$4,$5,$6)`, grant.EnrollmentID, message.SessionEpoch, message.SessionID, message.BootID, message.SigningKeyID, at); err != nil {
			return receipt, err
		}
		if _, err = tx.Exec(ctx, `UPDATE gp06f_telemetry_enrollments SET highest_epoch=$2 WHERE enrollment_id=$1`, grant.EnrollmentID, message.SessionEpoch); err != nil {
			return receipt, err
		}
	case "FINALIZE":
		var sessionKey, highest string
		var terminal *string
		if err = tx.QueryRow(ctx, `SELECT key_id,highest_received_sequence::text,last_allocated_sequence::text FROM gp06f_telemetry_sessions WHERE enrollment_id=$1 AND session_epoch=$2 AND session_id=$3 AND boot_id=$4`, grant.EnrollmentID, message.SessionEpoch, message.SessionID, message.BootID).Scan(&sessionKey, &highest, &terminal); err != nil {
			return receipt, err
		}
		if key.State == "VERIFY_ONLY" && sessionKey != key.ID {
			return receipt, telemetry.ErrUnauthorized
		}
		end, err := telemetryU64(message.LastAllocatedSequence)
		if err != nil {
			return receipt, err
		}
		received, err := telemetryU64(highest)
		if err != nil {
			return receipt, err
		}
		if received > end || terminal != nil {
			return receipt, telemetry.ErrConflict
		}
		for _, loss := range message.Loss {
			if loss.Range.AffectedKey.SessionEpoch != message.SessionEpoch || loss.Range.AffectedKey.SessionID != message.SessionID {
				return receipt, telemetry.ErrInvalid
			}
			last, e := telemetryU64(loss.Range.ThroughSequence)
			if e != nil || last > end {
				return receipt, telemetry.ErrInvalid
			}
		}
		if err = storeTelemetryLosses(ctx, tx, grant, message.Loss); err != nil {
			return receipt, err
		}
		var maximum *string
		if err = tx.QueryRow(ctx, `SELECT max(through_sequence)::text FROM gp06f_telemetry_intervals WHERE enrollment_id=$1 AND session_epoch=$2`, grant.EnrollmentID, message.SessionEpoch).Scan(&maximum); err != nil {
			return receipt, err
		}
		if maximum != nil {
			last, e := telemetryU64(*maximum)
			if e != nil {
				return receipt, e
			}
			if last > end {
				return receipt, telemetry.ErrConflict
			}
		}
		if _, err = tx.Exec(ctx, `UPDATE gp06f_telemetry_sessions SET finalized_at=$3,last_allocated_sequence=$4,retired_at=CASE WHEN node_completed_through=$4::numeric AND ($4::numeric>0 OR empty_release_completed) THEN coalesce(retired_at,$3) ELSE retired_at END WHERE enrollment_id=$1 AND session_epoch=$2`, grant.EnrollmentID, message.SessionEpoch, at, message.LastAllocatedSequence); err != nil {
			return receipt, err
		}
		if err = advanceRetiredEpoch(ctx, tx, grant.EnrollmentID); err != nil {
			return receipt, err
		}
	default:
		return receipt, telemetry.ErrInvalid
	}
	body, err := json.Marshal(message)
	if err != nil || len(body) > telemetry.MaxBatchBytes {
		return receipt, telemetry.ErrInvalid
	}
	receipt = telemetrySessionReceipt(message, telemetryReceiptID(message.Kind, grant.EnrollmentID, message.SessionEpoch, "", message.Digest), at)
	if err = populateTelemetrySessionCoverage(ctx, tx, grant, &receipt); err != nil {
		return receipt, err
	}
	receiptBody, err := json.Marshal(receipt)
	if err != nil {
		return receipt, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO gp06f_telemetry_lifecycle(enrollment_id,session_epoch,session_id,kind,digest,message,receipt_id,stored_at,receipt) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, grant.EnrollmentID, message.SessionEpoch, message.SessionID, message.Kind, message.Digest, body, receipt.ID, at, receiptBody); err != nil {
		return receipt, err
	}
	return receipt, tx.Commit(ctx)
}
func telemetrySessionReceipt(m telemetry.SessionMessage, id string, at time.Time) telemetry.SessionReceipt {
	return telemetry.SessionReceipt{ProtocolVersion: 1, ID: id, ClusterID: m.ClusterID, NodeID: m.NodeID, EnrollmentID: m.EnrollmentID, EnrollmentRevision: m.EnrollmentRevision, SessionEpoch: m.SessionEpoch, SessionID: m.SessionID, BootID: m.BootID, Kind: m.Kind, Digest: m.Digest, StoredAt: at, Durability: "CLOUD"}
}
func populateTelemetrySessionCoverage(ctx context.Context, tx pgx.Tx, g telemetry.Grant, r *telemetry.SessionReceipt) error {
	var terminal *string
	if err := tx.QueryRow(ctx, `SELECT last_allocated_sequence::text,retired_at IS NOT NULL FROM gp06f_telemetry_sessions WHERE enrollment_id=$1 AND session_epoch=$2`, g.EnrollmentID, r.SessionEpoch).Scan(&terminal, &r.Retired); err != nil {
		return err
	}
	r.Finalized = terminal != nil
	if terminal != nil {
		end, err := telemetryU64(*terminal)
		if err != nil {
			return err
		}
		all, err := loadTelemetryIntervals(ctx, tx, g.EnrollmentID, r.SessionEpoch)
		if err != nil {
			return err
		}
		r.Covered = telemetryCovered(all, g.Sources, end)
	}
	return nil
}

func (s *TelemetryStore) acceptBatch(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, batch telemetry.NodeBatch, gatewayReceiptID string) (receipt telemetry.CloudReceipt, err error) {
	if !telemetry.ValidIdentifier(gatewayReceiptID) {
		return receipt, telemetry.ErrInvalid
	}
	if telemetry.ValidateNodeBatch(batch) != nil {
		return receipt, telemetry.ErrInvalid
	}
	body, err := json.Marshal(batch)
	if err != nil || len(body) > telemetry.MaxNodeBatchBytes {
		return receipt, telemetry.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := beginTelemetryTx(ctx, s.pool)
	if err != nil {
		return receipt, err
	}
	defer rollbackMonitoringTx(tx)
	var at time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return receipt, err
	}
	grant, err := loadTelemetryGrant(ctx, tx, cluster, collector, batch.Key.EnrollmentID, at, true)
	if err != nil {
		return receipt, err
	}
	if err = telemetry.ValidateBatchForGrant(batch, grant, at); err != nil {
		return receipt, err
	}
	key, public, err := telemetrySigningKey(grant, batch.SigningKeyID)
	if err != nil {
		return receipt, err
	}
	if err = telemetry.VerifyBatchSignature(batch, public); err != nil {
		return receipt, telemetry.ErrUnauthorized
	}
	var sessionKey string
	var terminal *string
	if err = tx.QueryRow(ctx, `SELECT key_id,last_allocated_sequence::text FROM gp06f_telemetry_sessions WHERE enrollment_id=$1 AND session_epoch=$2 AND session_id=$3 AND boot_id=$4`, grant.EnrollmentID, batch.Key.SessionEpoch, batch.Key.SessionID, batch.BootID).Scan(&sessionKey, &terminal); err != nil {
		return receipt, err
	}
	if sessionKey != key.ID {
		return receipt, telemetry.ErrUnauthorized
	}
	seq, err := telemetryU64(batch.Key.Sequence)
	if err != nil {
		return receipt, err
	}
	// A carrier cannot simultaneously declare its own source sequence lost.
	// Validate before receipt lookup as well as before storing any loss facts.
	for _, source := range batch.Sources {
		for _, loss := range source.Loss {
			if loss.AffectedKey.SessionEpoch != batch.Key.SessionEpoch || loss.AffectedKey.SessionID != batch.Key.SessionID {
				continue
			}
			first, firstErr := telemetryU64(loss.AffectedKey.Sequence)
			last, lastErr := telemetryU64(loss.ThroughSequence)
			if firstErr != nil || lastErr != nil || first <= seq && seq <= last {
				return receipt, telemetry.ErrConflict
			}
		}
	}
	if terminal != nil {
		end, e := telemetryU64(*terminal)
		if e != nil {
			return receipt, e
		}
		if seq > end {
			return receipt, telemetry.ErrConflict
		}
	}
	var digest, previousGateway string
	err = tx.QueryRow(ctx, `SELECT digest,gateway_receipt_id,receipt_id,stored_at,history_only FROM gp06f_telemetry_batches WHERE enrollment_id=$1 AND session_epoch=$2 AND sequence=$3`, grant.EnrollmentID, batch.Key.SessionEpoch, batch.Key.Sequence).Scan(&digest, &previousGateway, &receipt.ID, &receipt.StoredAt, &receipt.HistoryOnly)
	if err == nil {
		if digest != batch.Digest || previousGateway != gatewayReceiptID {
			return receipt, telemetry.ErrConflict
		}
		receipt.ProtocolVersion = 1
		receipt.Key = batch.Key
		receipt.Digest = digest
		receipt.GatewayReceiptID = previousGateway
		receipt.Durability = "CLOUD"
		return receipt, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return receipt, err
	}
	fenced, err := telemetryRetirementFenced(ctx, tx, grant.EnrollmentID, batch.Key.SessionEpoch, seq, seq)
	if err != nil {
		return receipt, err
	}
	if fenced {
		return receipt, telemetry.ErrConflict
	}
	var losses []telemetry.SessionLoss
	for _, source := range batch.Sources {
		for _, loss := range source.Loss {
			losses = append(losses, telemetry.SessionLoss{SourceID: source.SourceID, Range: loss})
		}
	}
	if err = storeTelemetryLosses(ctx, tx, grant, losses); err != nil {
		return receipt, err
	}
	if err = persistTelemetryInterval(ctx, tx, grant.EnrollmentID, batch.Key.SessionEpoch, telemetryInterval{kind: "RECEIVED", from: seq, through: seq}); err != nil {
		return receipt, err
	}
	// The initial fixture profile always remains synthetic history; no intake
	// receipt establishes physical freshness or feeds a health projection.
	historyOnly := true
	receipt = telemetry.CloudReceipt{ProtocolVersion: 1, ID: telemetryReceiptID("BATCH", grant.EnrollmentID, batch.Key.SessionEpoch, batch.Key.Sequence, batch.Digest), Key: batch.Key, Digest: batch.Digest, GatewayReceiptID: gatewayReceiptID, StoredAt: at, Durability: "CLOUD", HistoryOnly: historyOnly}
	if _, err = tx.Exec(ctx, `INSERT INTO gp06f_telemetry_batches(enrollment_id,session_epoch,session_id,sequence,digest,gateway_receipt_id,receipt_id,body,history_only,stored_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, grant.EnrollmentID, batch.Key.SessionEpoch, batch.Key.SessionID, batch.Key.Sequence, batch.Digest, gatewayReceiptID, receipt.ID, body, historyOnly, at); err != nil {
		return receipt, err
	}
	if _, err = tx.Exec(ctx, `UPDATE gp06f_telemetry_sessions SET highest_received_sequence=greatest(highest_received_sequence,$3::numeric) WHERE enrollment_id=$1 AND session_epoch=$2`, grant.EnrollmentID, batch.Key.SessionEpoch, strconv.FormatUint(seq, 10)); err != nil {
		return receipt, err
	}
	return receipt, tx.Commit(ctx)
}

// A bounded fresh transaction retries serialization/unique races, then
// independently revalidates authority and immutable identity. Enrollment locks
// fence multi-query state; READ COMMITTED sees inventory commits after fact-lock
// waits instead of retaining an older governing inventory snapshot.
func (s *TelemetryStore) RegisterSession(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, message telemetry.SessionMessage) (receipt telemetry.SessionReceipt, err error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = retryTelemetryTransaction(ctx, func() error {
		var attemptErr error
		receipt, attemptErr = s.registerSession(ctx, cluster, collector, message)
		return attemptErr
	})
	return receipt, telemetrySafeError(err)
}
func (s *TelemetryStore) AcceptBatch(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, batch telemetry.NodeBatch, gatewayReceiptID string) (receipt telemetry.CloudReceipt, err error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = retryTelemetryTransaction(ctx, func() error {
		var attemptErr error
		receipt, attemptErr = s.acceptBatch(ctx, cluster, collector, batch, gatewayReceiptID)
		return attemptErr
	})
	return receipt, telemetrySafeError(err)
}
