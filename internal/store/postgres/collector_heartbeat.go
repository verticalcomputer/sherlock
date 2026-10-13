package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
)

func (s *CollectorControlStore) RecordHeartbeat(ctx context.Context, heartbeat collectorcontrol.Heartbeat) error {
	if err := collectorcontrol.ValidateHeartbeat(heartbeat, heartbeat.ReportedAt); err != nil {
		return err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin collector heartbeat: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	minimum, maximum := heartbeat.ProtocolRange()
	sourceIDs := make([]string, 0, len(heartbeat.SourceHealth))
	for _, source := range heartbeat.SourceHealth {
		sourceIDs = append(sourceIDs, string(source.SourceID))
	}
	result, err := tx.Exec(ctx, `
		UPDATE collectors SET version=$2, build_commit=$3, protocol_min=$4, protocol_max=$5, last_heartbeat_at=clock_timestamp(),reported_source_ids=$6
		WHERE collector_id=$1 AND status='ACTIVE'`, heartbeat.CollectorID, heartbeat.Version, heartbeat.BuildCommit, minimum, maximum, sourceIDs)
	if err != nil {
		return fmt.Errorf("update collector heartbeat %s: %w", heartbeat.CollectorID, err)
	}
	if result.RowsAffected() != 1 {
		return collectorcontrol.ErrCollectorInactive
	}
	if _, err := tx.Exec(ctx, `DELETE FROM collector_capabilities WHERE collector_id=$1`, heartbeat.CollectorID); err != nil {
		return fmt.Errorf("replace collector capabilities %s: %w", heartbeat.CollectorID, err)
	}
	for _, capability := range heartbeat.Capabilities {
		if _, err := tx.Exec(ctx, `INSERT INTO collector_capabilities (collector_id, capability, version) VALUES ($1,$2,$3)`, heartbeat.CollectorID, capability.Name, capability.Version); err != nil {
			return fmt.Errorf("record collector capability %s: %w", heartbeat.CollectorID, err)
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM collector_command_packs WHERE collector_id=$1`, heartbeat.CollectorID); err != nil {
		return fmt.Errorf("replace collector command packs %s: %w", heartbeat.CollectorID, err)
	}
	for _, pack := range heartbeat.CommandPacks {
		if _, err := tx.Exec(ctx, `INSERT INTO collector_command_packs (collector_id, pack_id, version, digest_sha256) VALUES ($1,$2,$3,decode($4,'hex'))`, heartbeat.CollectorID, pack.PackID, pack.Version, pack.DigestSHA256); err != nil {
			return fmt.Errorf("record collector command pack %s: %w", heartbeat.CollectorID, err)
		}
	}
	for _, source := range heartbeat.SourceHealth {
		result, err := tx.Exec(ctx, `
			INSERT INTO collector_source_health (collector_id, source_id, availability, safe_message, checked_at)
			SELECT $1, s.source_id, $3, $4, $5 FROM sources s JOIN collectors c ON c.cluster_id=s.cluster_id
			WHERE s.source_id=$2 AND c.collector_id=$1
			ON CONFLICT (collector_id, source_id) DO UPDATE SET
				availability=CASE WHEN collector_source_health.checked_at <= EXCLUDED.checked_at THEN EXCLUDED.availability ELSE collector_source_health.availability END,
				safe_message=CASE WHEN collector_source_health.checked_at <= EXCLUDED.checked_at THEN EXCLUDED.safe_message ELSE collector_source_health.safe_message END,
				checked_at=GREATEST(collector_source_health.checked_at, EXCLUDED.checked_at), reported_at=clock_timestamp()`,
			heartbeat.CollectorID, source.SourceID, source.Availability, source.SafeMessage, source.CheckedAt.UTC())
		if err != nil {
			return fmt.Errorf("record source health for collector %s: %w", heartbeat.CollectorID, err)
		}
		if result.RowsAffected() != 1 {
			return fmt.Errorf("source health target is outside collector cluster or older than current state")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit collector heartbeat %s: %w", heartbeat.CollectorID, err)
	}
	return nil
}
