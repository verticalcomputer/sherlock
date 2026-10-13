package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func (s *TelemetryStore) Status(ctx context.Context, cluster domain.ClusterID, collector domain.CollectorID, id string) (out telemetry.EnrollmentStatus, err error) {
	defer func() { err = telemetrySafeError(err) }()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := beginTelemetryTx(ctx, s.pool)
	if err != nil {
		return out, err
	}
	defer rollbackMonitoringTx(tx)
	var at time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return out, err
	}
	out.Grant, err = loadTelemetryGrant(ctx, tx, cluster, collector, id, at, false)
	if err != nil {
		return out, err
	}
	rows, err := tx.Query(ctx, `SELECT session_epoch::text,session_id,boot_id,key_id,last_allocated_sequence::text,highest_received_sequence::text,retired_at IS NOT NULL FROM gp06f_telemetry_sessions WHERE enrollment_id=$1 ORDER BY session_epoch DESC LIMIT 33`, id)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var session telemetry.SessionStatus
		var terminal *string
		if err = rows.Scan(&session.SessionEpoch, &session.SessionID, &session.BootID, &session.SigningKeyID, &terminal, &session.HighestReceivedSequence, &session.Retired); err != nil {
			rows.Close()
			return out, err
		}
		if len(out.Sessions) == telemetry.MaxStatusSessions {
			out.SessionsTruncated = true
			out.SessionsOmittedLowerBound = 1
			break
		}
		if terminal != nil {
			session.Finalized = true
			session.LastAllocatedSequence = *terminal
		}
		out.Sessions = append(out.Sessions, session)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	lossLeft := telemetry.MaxStatusRanges
	for i := range out.Sessions {
		session := &out.Sessions[i]
		all, e := loadTelemetryIntervals(ctx, tx, id, session.SessionEpoch)
		if e != nil {
			return out, e
		}
		if session.Finalized {
			terminal, e := telemetryU64(session.LastAllocatedSequence)
			if e != nil {
				return out, e
			}
			session.Covered = telemetryCovered(all, out.Grant.Sources, terminal)
		}
		for _, interval := range all {
			if interval.kind != "RECEIVED" {
				continue
			}
			if len(session.ReceivedRanges) == telemetry.MaxStatusRanges {
				session.RangesTruncated = true
				session.OmittedRangesLowerBound++
				continue
			}
			session.ReceivedRanges = append(session.ReceivedRanges, telemetry.SequenceRange{From: formatTelemetryU64(interval.from), Through: formatTelemetryU64(interval.through)})
		}
		lossRows, e := tx.Query(ctx, `SELECT source_id,fact FROM gp06f_telemetry_loss WHERE enrollment_id=$1 AND session_epoch=$2 ORDER BY stored_at DESC,loss_id LIMIT 17`, id, session.SessionEpoch)
		if e != nil {
			return out, e
		}
		for lossRows.Next() {
			var loss telemetry.SessionLoss
			var body []byte
			if e = lossRows.Scan(&loss.SourceID, &body); e != nil {
				lossRows.Close()
				return out, e
			}
			if lossLeft == 0 {
				session.LossTruncated = true
				session.OmittedLossLowerBound = 1
				break
			}
			if e = json.Unmarshal(body, &loss.Range); e != nil {
				lossRows.Close()
				return out, e
			}
			session.Loss = append(session.Loss, loss)
			lossLeft--
		}
		e = lossRows.Err()
		lossRows.Close()
		if e != nil {
			return out, e
		}
	}
	rows, err = tx.Query(ctx, `SELECT session_epoch::text,session_id,sequence::text,digest,gateway_receipt_id,receipt_id,stored_at,history_only FROM gp06f_telemetry_batches WHERE enrollment_id=$1 ORDER BY stored_at DESC,session_epoch DESC,sequence DESC LIMIT 65`, id)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var receipt telemetry.CloudReceipt
		receipt.ProtocolVersion = 1
		receipt.Key.ClusterID = string(cluster)
		receipt.Key.NodeID = out.Grant.NodeID
		receipt.Key.EnrollmentID = id
		receipt.Durability = "CLOUD"
		if err = rows.Scan(&receipt.Key.SessionEpoch, &receipt.Key.SessionID, &receipt.Key.Sequence, &receipt.Digest, &receipt.GatewayReceiptID, &receipt.ID, &receipt.StoredAt, &receipt.HistoryOnly); err != nil {
			rows.Close()
			return out, err
		}
		if len(out.Receipts) == telemetry.MaxStatusReceipts {
			out.ReceiptsTruncated = true
			out.ReceiptsOmittedLowerBound = 1
			break
		}
		out.Receipts = append(out.Receipts, receipt)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	// Only the fixture schema is readable here. One row is processed at a time;
	// source coverage/support remains original, records/loss omissions explicit.
	rows, err = tx.Query(ctx, `SELECT body,stored_at,history_only FROM gp06f_telemetry_batches WHERE enrollment_id=$1 ORDER BY stored_at DESC,session_epoch DESC,sequence DESC LIMIT 17`, id)
	if err != nil {
		return out, err
	}
	recordsLeft := telemetry.MaxStatusRecords
	for rows.Next() {
		var body []byte
		var item telemetry.BatchHistory
		if err = rows.Scan(&body, &item.StoredAt, &item.HistoryOnly); err != nil {
			rows.Close()
			return out, err
		}
		if len(out.History) == telemetry.MaxStatusHistory {
			out.HistoryTruncated = true
			out.HistoryOmittedLowerBound = 1
			break
		}
		var batch telemetry.NodeBatch
		if err = json.Unmarshal(body, &batch); err != nil {
			rows.Close()
			return out, err
		}
		item.Key = batch.Key
		item.Digest = batch.Digest
		for _, source := range batch.Sources {
			count := len(source.Records)
			item.RecordCount += int64(count)
			keep := count
			if keep > recordsLeft {
				keep = recordsLeft
			}
			source.Records = source.Records[:keep]
			recordsLeft -= keep
			if keep < count {
				item.RecordsTruncated = true
				item.OmittedRecordsLowerBound += int64(count - keep)
			}
			item.LossCount += int64(len(source.Loss))
			item.OmittedLossLowerBound += int64(len(source.Loss))
			item.LossTruncated = item.LossTruncated || len(source.Loss) > 0
			source.Loss = nil
			item.Sources = append(item.Sources, source)
		}
		out.History = append(out.History, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	// Global serialization bound may tighten the fixed row maxima for unusually
	// long approved identifiers. Drop whole summaries with explicit lower-bound
	// omissions; never strip values/support and present them as complete.
	for {
		if ctx.Err() != nil {
			return telemetry.EnrollmentStatus{}, ctx.Err()
		}
		body, e := json.Marshal(out)
		if e != nil {
			return telemetry.EnrollmentStatus{}, e
		}
		if len(body) <= telemetry.MaxStatusBytes {
			break
		}
		switch {
		case len(out.History) > 0:
			out.History = out.History[:len(out.History)-1]
			out.HistoryTruncated = true
			out.HistoryOmittedLowerBound++
		case len(out.Receipts) > 0:
			out.Receipts = out.Receipts[:len(out.Receipts)-1]
			out.ReceiptsTruncated = true
			out.ReceiptsOmittedLowerBound++
		case len(out.Sessions) > 0:
			out.Sessions = out.Sessions[:len(out.Sessions)-1]
			out.SessionsTruncated = true
			out.SessionsOmittedLowerBound++
		default:
			return telemetry.EnrollmentStatus{}, telemetry.ErrBackpressure
		}
	}
	return out, tx.Commit(ctx)
}
