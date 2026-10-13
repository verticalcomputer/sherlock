package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func recordSlurmSnapshotTx(ctx context.Context, tx pgx.Tx, runID domain.RunID, payload domain.SlurmSnapshotPayload) error {
	if payload.Inventory != nil {
		if _, err := recordInventoryRevisionTx(ctx, tx, application.InventoryObserved, *payload.Inventory); err != nil {
			return err
		}
	}
	for _, fact := range payload.Allocations {
		if err := recordSlurmAllocationFactTx(ctx, tx, runID, fact); err != nil {
			return err
		}
	}
	for _, lifecycle := range payload.Lifecycles {
		if err := recordSlurmLifecycleTx(ctx, tx, runID, lifecycle); err != nil {
			return err
		}
	}
	for _, unresolved := range payload.UnresolvedAccounting {
		if err := recordUnresolvedSlurmAccountingTx(ctx, tx, runID, unresolved); err != nil {
			return err
		}
	}
	for i, issue := range payload.Issues {
		document, err := json.Marshal(issue)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO goodput_slurm_snapshot_issues(run_id,ordinal,document) VALUES($1,$2,$3)`, runID, i, document); err != nil {
			return fmt.Errorf("insert Slurm snapshot issue: %w", err)
		}
	}
	for _, source := range payload.Sources {
		document, err := json.Marshal(source)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO goodput_slurm_snapshot_sources(run_id,source_kind,document) VALUES($1,$2,$3)`, runID, source.Kind, document); err != nil {
			return fmt.Errorf("insert Slurm snapshot provenance: %w", err)
		}
	}
	return nil
}

func recordSlurmAllocationFactTx(ctx context.Context, tx pgx.Tx, runID domain.RunID, fact domain.SlurmAllocationFact) error {
	recordID := domain.CanonicalSlurmAllocationRecordID(fact.Snapshot)
	if fact.RecordIdentity != recordID {
		return resultConflict("Slurm allocation record identity is not canonical")
	}
	core := fact.Snapshot
	core.SourceAt, core.ObservedAt = core.EffectiveAt, core.EffectiveAt
	core.Entities = slices.Clone(core.Entities)
	slices.SortFunc(core.Entities, func(a, b domain.EntityIdentity) int { return strings.Compare(a.Key(), b.Key()) })
	document, _ := json.Marshal(core)
	digest := sha256.Sum256(document)
	if err := lockGoodputFactStream(ctx, tx, "slurm-allocation", core.ClusterID, core.SourceID, ""); err != nil {
		return err
	}
	var storedDigest []byte
	err := tx.QueryRow(ctx, `SELECT core_sha256 FROM goodput_slurm_allocation_facts WHERE cluster_id=$1 AND source_id=$2 AND record_identity=$3`, core.ClusterID, core.SourceID, recordID).Scan(&storedDigest)
	if err == pgx.ErrNoRows {
		if _, err = recordAllocationSnapshotTx(ctx, tx, fact.Snapshot); err != nil {
			return err
		}
		key := allocationSnapshotKey(fact.Snapshot)
		if _, err = tx.Exec(ctx, `INSERT INTO goodput_slurm_allocation_facts(cluster_id,source_id,record_identity,snapshot_key,core_sha256,first_run_id) VALUES($1,$2,$3,$4,$5,$6)`, core.ClusterID, core.SourceID, recordID, key, digest[:], runID); err != nil {
			return fmt.Errorf("insert Slurm allocation identity: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("load Slurm allocation identity: %w", err)
	} else if subtle.ConstantTimeCompare(storedDigest, digest[:]) != 1 {
		return resultConflict("Slurm allocation identity conflicts with immutable evidence")
	}
	if _, err = tx.Exec(ctx, `INSERT INTO goodput_slurm_allocation_observations(cluster_id,source_id,record_identity,run_id,source_at,observed_at) VALUES($1,$2,$3,$4,$5,$6)`, core.ClusterID, core.SourceID, recordID, runID, fact.Snapshot.SourceAt, fact.Snapshot.ObservedAt); err != nil {
		return fmt.Errorf("insert Slurm allocation observation: %w", err)
	}
	return nil
}

func recordSlurmLifecycleTx(ctx context.Context, tx pgx.Tx, runID domain.RunID, lifecycle domain.SlurmJobLifecycle) error {
	recordID := domain.CanonicalSlurmLifecycleRecordID(lifecycle)
	if lifecycle.RecordIdentity != recordID {
		return resultConflict("Slurm lifecycle record identity is not canonical")
	}
	core := lifecycle
	core.RecordIdentity = ""
	document, _ := json.Marshal(core)
	digest := sha256.Sum256(document)
	if err := lockGoodputFactStream(ctx, tx, "slurm-lifecycle", lifecycle.ClusterID, lifecycle.SourceID, ""); err != nil {
		return err
	}
	if err := insertImmutableSlurmDocument(ctx, tx, `goodput_slurm_lifecycle_facts`, lifecycle.ClusterID, lifecycle.SourceID, recordID, document, digest, runID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO goodput_slurm_lifecycle_observations(cluster_id,source_id,record_identity,run_id) VALUES($1,$2,$3,$4)`, lifecycle.ClusterID, lifecycle.SourceID, recordID, runID); err != nil {
		return fmt.Errorf("insert Slurm lifecycle observation: %w", err)
	}
	return nil
}

func recordUnresolvedSlurmAccountingTx(ctx context.Context, tx pgx.Tx, runID domain.RunID, record domain.SlurmUnresolvedAccounting) error {
	recordID := domain.CanonicalSlurmUnresolvedRecordID(record)
	if record.RecordIdentity != recordID {
		return resultConflict("unresolved Slurm accounting identity is not canonical")
	}
	core := record
	core.RecordIdentity, core.Provenance = "", nil
	document, _ := json.Marshal(core)
	digest := sha256.Sum256(document)
	if err := lockGoodputFactStream(ctx, tx, "slurm-unresolved", record.ClusterID, record.SourceID, ""); err != nil {
		return err
	}
	if err := insertImmutableSlurmDocument(ctx, tx, `goodput_slurm_unresolved_accounting`, record.ClusterID, record.SourceID, recordID, document, digest, runID); err != nil {
		return err
	}
	for _, provenance := range record.Provenance {
		if _, err := tx.Exec(ctx, `INSERT INTO goodput_slurm_accounting_provenance(cluster_id,source_id,record_identity,run_id,window_start,window_end,source_at,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, record.ClusterID, record.SourceID, recordID, runID, provenance.WindowStart, provenance.WindowEnd, provenance.SourceAt, provenance.ObservedAt); err != nil {
			return fmt.Errorf("insert Slurm accounting provenance: %w", err)
		}
	}
	return nil
}

func insertImmutableSlurmDocument(ctx context.Context, tx pgx.Tx, table string, clusterID domain.ClusterID, sourceID domain.SourceID, recordID string, document []byte, digest [sha256.Size]byte, runID domain.RunID) error {
	command, err := tx.Exec(ctx, `INSERT INTO `+table+`(cluster_id,source_id,record_identity,document,core_sha256,first_run_id) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, clusterID, sourceID, recordID, document, digest[:], runID)
	if err != nil {
		return fmt.Errorf("insert immutable Slurm evidence: %w", err)
	}
	if command.RowsAffected() != 0 {
		return nil
	}
	var stored []byte
	if err := tx.QueryRow(ctx, `SELECT core_sha256 FROM `+table+` WHERE cluster_id=$1 AND source_id=$2 AND record_identity=$3`, clusterID, sourceID, recordID).Scan(&stored); err != nil {
		return fmt.Errorf("load immutable Slurm evidence: %w", err)
	}
	if subtle.ConstantTimeCompare(stored, digest[:]) != 1 {
		return resultConflict("Slurm evidence identity conflicts with immutable evidence")
	}
	return nil
}
