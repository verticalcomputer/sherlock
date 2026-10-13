package postgres

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigator"
)

// Schedule detections are committed before their investigations are created.
// Ownership follows this durable cluster/investigation/incident join, never a
// requester string or an identifier prefix. Keep it on selection as well as
// seeding so old claim rows cannot be adopted by the general worker.
const generalInvestigation = `NOT EXISTS (
 SELECT 1 FROM schedule_repair_detections d
 WHERE d.cluster_id=i.cluster_id AND d.investigation_id=i.investigation_id
 AND d.incident_id=i.incident_id)`

type InvestigationLeaseStore struct{ pool *pgxpool.Pool }

func NewInvestigationLeaseStore(pool *pgxpool.Pool) (*InvestigationLeaseStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("investigation lease pool is required")
	}
	return &InvestigationLeaseStore{pool: pool}, nil
}

func (store *InvestigationLeaseStore) Claim(ctx context.Context, owner string, now time.Time, ttl time.Duration, maxGlobal, maxPerCluster int) (investigator.Lease, bool, error) {
	if owner == "" || ttl <= 0 || maxGlobal < 1 || maxPerCluster < 1 || maxPerCluster > maxGlobal {
		return investigator.Lease{}, false, fmt.Errorf("investigation lease claim is invalid")
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return investigator.Lease{}, false, fmt.Errorf("generate lease token: %w", err)
	}
	digest := domain.ChecksumSHA256(token)
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return investigator.Lease{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Serialize only the short capacity-and-claim transaction across replicas.
	// Provider work never holds this advisory lock.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('sherlock-investigator-capacity'))`); err != nil {
		return investigator.Lease{}, false, fmt.Errorf("lock investigator capacity: %w", err)
	}
	var active int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM investigation_claims c JOIN investigations i USING(investigation_id,cluster_id) WHERE c.status='LEASED' AND c.lease_expires_at > $1 AND `+generalInvestigation, now.UTC()).Scan(&active); err != nil {
		return investigator.Lease{}, false, fmt.Errorf("count active investigation claims: %w", err)
	}
	if active >= maxGlobal {
		if err := tx.Commit(ctx); err != nil {
			return investigator.Lease{}, false, err
		}
		return investigator.Lease{}, false, nil
	}
	_, err = tx.Exec(ctx, `INSERT INTO investigation_claims (investigation_id,cluster_id,available_at) SELECT i.investigation_id,i.cluster_id,$1 FROM investigations i WHERE i.status NOT IN ('COMPLETED','PARTIAL','BLOCKED','CANCELLED','AWAITING_APPROVAL') AND `+generalInvestigation+` ON CONFLICT DO NOTHING`, now.UTC())
	if err != nil {
		return investigator.Lease{}, false, fmt.Errorf("seed investigation claims: %w", err)
	}
	var id domain.InvestigationID
	var epoch int64
	err = tx.QueryRow(ctx, `SELECT c.investigation_id,c.lease_epoch FROM investigation_claims c JOIN investigations i ON i.investigation_id=c.investigation_id WHERE `+generalInvestigation+` AND i.status NOT IN ('COMPLETED','PARTIAL','BLOCKED','CANCELLED','AWAITING_APPROVAL') AND ((c.status='AVAILABLE' AND c.available_at <= $1) OR (c.status='LEASED' AND c.lease_expires_at <= $1)) AND (SELECT count(*) FROM investigation_claims pc JOIN investigations i ON i.investigation_id=pc.investigation_id AND i.cluster_id=pc.cluster_id WHERE pc.cluster_id=c.cluster_id AND pc.status='LEASED' AND pc.lease_expires_at > $1 AND `+generalInvestigation+`) < $2 ORDER BY i.updated_at,c.investigation_id FOR UPDATE OF c SKIP LOCKED LIMIT 1`, now.UTC(), maxPerCluster).Scan(&id, &epoch)
	if err != nil {
		if err == pgx.ErrNoRows {
			if commitErr := tx.Commit(ctx); commitErr != nil {
				return investigator.Lease{}, false, commitErr
			}
			return investigator.Lease{}, false, nil
		}
		return investigator.Lease{}, false, fmt.Errorf("select investigation claim: %w", err)
	}
	epoch++
	command, err := tx.Exec(ctx, `UPDATE investigation_claims SET status='LEASED',lease_owner=$2,lease_token_hash=$3,lease_expires_at=$4,lease_epoch=$5,attempt_count=attempt_count+1,last_heartbeat_at=$1,updated_at=$1 WHERE investigation_id=$6`, now.UTC(), owner, digest[:], now.Add(ttl).UTC(), epoch, id)
	if err != nil {
		return investigator.Lease{}, false, fmt.Errorf("acquire investigation claim: %w", err)
	}
	if command.RowsAffected() != 1 {
		return investigator.Lease{}, false, fmt.Errorf("acquire investigation claim: row was not updated")
	}
	if err := tx.Commit(ctx); err != nil {
		return investigator.Lease{}, false, err
	}
	return investigator.Lease{InvestigationID: id, Owner: owner, TokenHash: digest, Epoch: epoch}, true, nil
}

func (store *InvestigationLeaseStore) Heartbeat(ctx context.Context, lease investigator.Lease, now time.Time, ttl time.Duration) error {
	command, err := store.pool.Exec(ctx, `UPDATE investigation_claims c SET lease_expires_at=$1,last_heartbeat_at=$2,updated_at=$2 FROM investigations i WHERE i.investigation_id=c.investigation_id AND i.cluster_id=c.cluster_id AND c.investigation_id=$3 AND c.status='LEASED' AND c.lease_owner=$4 AND c.lease_token_hash=$5 AND c.lease_epoch=$6 AND `+generalInvestigation, now.Add(ttl).UTC(), now.UTC(), lease.InvestigationID, lease.Owner, lease.TokenHash[:], lease.Epoch)
	if err != nil {
		return fmt.Errorf("heartbeat investigation claim: %w", err)
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("investigation claim was lost")
	}
	return nil
}

func (store *InvestigationLeaseStore) Release(ctx context.Context, lease investigator.Lease, now, availableAt time.Time) error {
	if availableAt.Before(now) {
		availableAt = now
	}
	command, err := store.pool.Exec(ctx, `UPDATE investigation_claims SET status='AVAILABLE',available_at=$6,lease_owner=NULL,lease_token_hash=NULL,lease_expires_at=NULL,updated_at=$1 WHERE investigation_id=$2 AND status='LEASED' AND lease_owner=$3 AND lease_token_hash=$4 AND lease_epoch=$5`, now.UTC(), lease.InvestigationID, lease.Owner, lease.TokenHash[:], lease.Epoch, availableAt.UTC())
	if err != nil {
		return fmt.Errorf("release investigation claim: %w", err)
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("investigation claim was lost")
	}
	return nil
}
