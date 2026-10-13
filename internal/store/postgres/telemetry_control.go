package postgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

// RevokeEnrollment is a permanent fence. Re-enrollment requires a new ID and
// reviewed recovery; matching old receipts do not bypass current revocation.
func (s *TelemetryStore) RevokeEnrollment(ctx context.Context, cluster domain.ClusterID, id string, expected int64, actor string) (revision int64, err error) {
	defer func() { err = telemetrySafeError(err) }()
	if expected < 1 || !monitoringID(actor, 128) {
		return 0, telemetry.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := beginTelemetryTx(ctx, s.pool)
	if err != nil {
		return 0, err
	}
	defer rollbackMonitoringTx(tx)
	var status string
	var current int64
	if err = tx.QueryRow(ctx, `SELECT status,control_revision FROM gp06f_telemetry_enrollments WHERE cluster_id=$1 AND enrollment_id=$2 FOR UPDATE`, cluster, id).Scan(&status, &current); err != nil {
		return 0, err
	}
	if current != expected || status != "ACTIVE" {
		return 0, telemetry.ErrConflict
	}
	var at time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return 0, err
	}
	revision = current + 1
	if _, err = tx.Exec(ctx, `UPDATE gp06f_telemetry_enrollments SET status='REVOKED',revoked_at=$3,control_revision=$4 WHERE cluster_id=$1 AND enrollment_id=$2`, cluster, id, at, revision); err != nil {
		return 0, err
	}
	if err = telemetryAudit(ctx, tx, id, revision, "REVOKED", actor, map[string]any{"replay_blocked": true}, at); err != nil {
		return 0, err
	}
	return revision, tx.Commit(ctx)
}

// RotateKey retains at most two current lifecycle keys. An older slot requires
// final node/gateway/cloud ownership proof before permanent archival; revocation
// alone never frees it. Immutable key identities and global epochs remain.
func (s *TelemetryStore) RotateKey(ctx context.Context, cluster domain.ClusterID, id string, expected int64, keyID, publicBase64, actor string, compromised bool) (grant telemetry.Grant, err error) {
	defer func() { err = telemetrySafeError(err) }()
	if expected < 1 || !monitoringID(actor, 128) {
		return grant, telemetry.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := beginTelemetryTx(ctx, s.pool)
	if err != nil {
		return grant, err
	}
	defer rollbackMonitoringTx(tx)
	var collector domain.CollectorID
	if err = tx.QueryRow(ctx, `SELECT gateway_collector_id FROM gp06f_telemetry_enrollments WHERE cluster_id=$1 AND enrollment_id=$2`, cluster, id).Scan(&collector); err != nil {
		return grant, err
	}
	var at time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return grant, err
	}
	grant, err = loadTelemetryGrant(ctx, tx, cluster, collector, id, at, true)
	if err != nil {
		return grant, err
	}
	if grant.ControlRevision != expected {
		return grant, telemetry.ErrConflict
	}
	if len(grant.Keys) >= 2 {
		if err = archiveTelemetryKey(ctx, tx, grant, at); err != nil {
			return grant, err
		}
		current := grant.Keys[:0]
		for _, key := range grant.Keys {
			if key.State == "ACTIVE" {
				current = append(current, key)
			}
		}
		grant.Keys = current
	}
	var highest string
	if err = tx.QueryRow(ctx, `SELECT max(key_epoch)::text FROM gp06f_telemetry_keys WHERE enrollment_id=$1`, id).Scan(&highest); err != nil {
		return grant, err
	}
	epoch, err := telemetryU64(highest)
	if err != nil || epoch == ^uint64(0) {
		return grant, telemetry.ErrBackpressure
	}
	next := telemetry.NodeKey{ID: keyID, Epoch: strconv.FormatUint(epoch+1, 10), PublicKeyBase64: publicBase64, State: "ACTIVE"}
	oldState := "VERIFY_ONLY"
	action := "KEY_ROTATED"
	if compromised {
		oldState = "REVOKED"
		action = "KEY_COMPROMISED"
	}
	for i := range grant.Keys {
		grant.Keys[i].State = oldState
	}
	grant.Keys = append(grant.Keys, next)
	grant.ControlRevision++
	if telemetry.ValidateGrant(grant, at) != nil {
		return grant, telemetry.ErrInvalid
	}
	public, _ := base64.RawStdEncoding.DecodeString(publicBase64)
	if _, err = tx.Exec(ctx, `UPDATE gp06f_telemetry_keys SET state=$2 WHERE enrollment_id=$1 AND state='ACTIVE' AND archived_at IS NULL`, id, oldState); err != nil {
		return grant, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO gp06f_telemetry_keys(enrollment_id,key_id,key_epoch,public_key,state,created_at) VALUES($1,$2,$3,$4,'ACTIVE',$5)`, id, keyID, next.Epoch, public, at); err != nil {
		return grant, err
	}
	if _, err = tx.Exec(ctx, `UPDATE gp06f_telemetry_enrollments SET control_revision=$2 WHERE enrollment_id=$1`, id, grant.ControlRevision); err != nil {
		return grant, err
	}
	if err = telemetryAudit(ctx, tx, id, grant.ControlRevision, action, actor, map[string]any{"new_key_id": keyID, "new_key_epoch": next.Epoch, "old_key_state": oldState, "retirement_available": true}, at); err != nil {
		return grant, err
	}
	return grant, tx.Commit(ctx)
}

// A known successor OPEN is required as well as at least one old session. Under
// the reviewed monotonic node allocator, sequential cloud OPEN admission then
// fences an undelivered predecessor; an empty set is never no-ownership proof.
func archiveTelemetryKey(ctx context.Context, tx pgx.Tx, grant telemetry.Grant, at time.Time) error {
	var old, active string
	for _, key := range grant.Keys {
		if key.State == "ACTIVE" {
			active = key.ID
		} else {
			old = key.ID
		}
	}
	if old == "" || active == "" {
		return telemetry.ErrBackpressure
	}
	var safe bool
	err := tx.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM gp06f_telemetry_sessions WHERE enrollment_id=$1 AND key_id=$2)
 AND NOT EXISTS(SELECT 1 FROM gp06f_telemetry_sessions WHERE enrollment_id=$1 AND key_id=$2 AND (finalized_at IS NULL OR retired_at IS NULL))
 AND EXISTS(SELECT 1 FROM gp06f_telemetry_sessions WHERE enrollment_id=$1 AND key_id=$3 AND session_epoch>(SELECT max(session_epoch) FROM gp06f_telemetry_sessions WHERE enrollment_id=$1 AND key_id=$2))
 AND NOT EXISTS(SELECT 1 FROM gp06f_telemetry_retirements r JOIN gp06f_telemetry_sessions s USING(enrollment_id,session_epoch) WHERE r.enrollment_id=$1 AND r.completed_at IS NULL AND (r.signing_key_id=$2 OR s.key_id=$2))`, grant.EnrollmentID, old, active).Scan(&safe)
	if err != nil {
		return err
	}
	if !safe {
		return telemetry.ErrBackpressure
	}
	_, err = tx.Exec(ctx, `UPDATE gp06f_telemetry_keys SET archived_at=$3 WHERE enrollment_id=$1 AND key_id=$2 AND archived_at IS NULL AND state<>'ACTIVE'`, grant.EnrollmentID, old, at)
	return err
}
