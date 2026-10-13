package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adminui"
	"github.com/verticalcomputer/sherlock/internal/platform"
)

// AdminAuditStore persists only the safe access metadata admitted by
// adminui.AuditEvent. It never receives credentials, Access JWTs, request
// bodies, rendered values, or backend error text.
type AdminAuditStore struct {
	pool *pgxpool.Pool
	ids  platform.RandomIDGenerator
}

func NewAdminAuditStore(pool *pgxpool.Pool) (*AdminAuditStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("admin audit PostgreSQL pool is required")
	}
	return &AdminAuditStore{pool: pool}, nil
}

func (store *AdminAuditStore) RecordAdminEvent(ctx context.Context, event adminui.AuditEvent) error {
	if !validAdminAuditEvent(event) {
		return fmt.Errorf("admin audit event is invalid")
	}
	eventID, err := store.ids.NewID()
	if err != nil {
		return err
	}
	var fingerprint []byte
	if len(event.SessionFingerprint) != 0 {
		fingerprint = append([]byte(nil), event.SessionFingerprint...)
	}
	_, err = store.pool.Exec(ctx, `
		INSERT INTO admin_dashboard_audit_events
			(event_id, event_kind, outcome, reason_code, session_fingerprint, request_id, occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		eventID, event.Kind, event.Outcome, event.ReasonCode, fingerprint, event.RequestID, event.OccurredAt.UTC())
	if err != nil {
		return fmt.Errorf("record admin audit event: %w", err)
	}
	return nil
}

func validAdminAuditEvent(event adminui.AuditEvent) bool {
	switch event.Kind {
	case adminui.EventAuthentication, adminui.EventSessionStarted, adminui.EventSessionEnded,
		adminui.EventSessionExpired, adminui.EventDashboardViewed,
		adminui.EventClusterUpdated, adminui.EventClusterRemoved:
	default:
		return false
	}
	if event.Outcome != adminui.OutcomeSucceeded && event.Outcome != adminui.OutcomeRejected {
		return false
	}
	if event.OccurredAt.IsZero() || len(event.ReasonCode) > 128 || len(event.RequestID) > 128 {
		return false
	}
	return len(event.SessionFingerprint) == 0 || len(event.SessionFingerprint) == 32
}
