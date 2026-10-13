package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const waitPollInterval = 50 * time.Millisecond

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, fmt.Errorf("PostgreSQL pool is required")
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Append(ctx context.Context, clusterID domain.ClusterID, payload Payload) (Event, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Event{}, fmt.Errorf("begin event append: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	event, err := s.AppendTx(ctx, tx, clusterID, payload)
	if err != nil {
		return Event{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Event{}, fmt.Errorf("commit event append for cluster %s: %w", clusterID, err)
	}
	return event, nil
}

// AppendTx atomically appends an event inside a caller-owned state-transition
// transaction. The per-cluster counter row serializes concurrent appenders.
func (s *Store) AppendTx(ctx context.Context, tx pgx.Tx, clusterID domain.ClusterID, payload Payload) (Event, error) {
	return AppendTx(ctx, tx, clusterID, payload)
}

// AppendTx is the package-level transactional integration point for PostgreSQL
// state stores. It avoids requiring those stores to construct a second Store.
func AppendTx(ctx context.Context, tx pgx.Tx, clusterID domain.ClusterID, payload Payload) (Event, error) {
	if tx == nil {
		return Event{}, fmt.Errorf("event append transaction is required")
	}
	if clusterID == "" {
		return Event{}, fmt.Errorf("event cluster identifier is required")
	}
	if payload == nil {
		return Event{}, fmt.Errorf("event payload is required")
	}
	if err := payload.validate(); err != nil {
		return Event{}, err
	}
	payload = normalizedPayload(payload)
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Event{}, fmt.Errorf("encode %s event payload: %w", payload.eventType(), err)
	}

	var id ID
	err = tx.QueryRow(ctx, `
		INSERT INTO event_streams (cluster_id, next_event_id) VALUES ($1, 2)
		ON CONFLICT (cluster_id) DO UPDATE
		SET next_event_id = event_streams.next_event_id + 1
		RETURNING next_event_id - 1`, clusterID).Scan(&id)
	if err != nil {
		return Event{}, fmt.Errorf("allocate event identifier for cluster %s: %w", clusterID, err)
	}

	event := Event{ClusterID: clusterID, ID: id, Type: payload.eventType(), SchemaVersion: payload.schemaVersion(), Payload: payload}
	err = tx.QueryRow(ctx, `
		INSERT INTO cluster_events (cluster_id, event_id, event_type, schema_version, payload)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING created_at`, clusterID, id, event.Type, event.SchemaVersion, encoded).Scan(&event.CreatedAt)
	if err != nil {
		return Event{}, fmt.Errorf("append event %d for cluster %s: %w", id, clusterID, err)
	}
	event.CreatedAt = event.CreatedAt.UTC()
	return event, nil
}

func normalizedPayload(payload Payload) Payload {
	switch value := payload.(type) {
	case CollectionUpdatedV1:
		value.CompletedAt = value.CompletedAt.UTC()
		return value
	case *CollectionUpdatedV1:
		copy := *value
		copy.CompletedAt = copy.CompletedAt.UTC()
		return copy
	case SourceUpdatedV1:
		value.LastAttemptAt = value.LastAttemptAt.UTC()
		if value.LastSuccessAt != nil {
			utc := value.LastSuccessAt.UTC()
			value.LastSuccessAt = &utc
		}
		return value
	case *SourceUpdatedV1:
		copy := *value
		copy.LastAttemptAt = copy.LastAttemptAt.UTC()
		if copy.LastSuccessAt != nil {
			utc := copy.LastSuccessAt.UTC()
			copy.LastSuccessAt = &utc
		}
		return copy
	default:
		return payload
	}
}

func (s *Store) ListAfter(ctx context.Context, clusterID domain.ClusterID, after ID, limit int) (Page, error) {
	if err := validateRead(clusterID, limit); err != nil {
		return Page{}, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT event_id, event_type, schema_version, payload, created_at
		FROM cluster_events
		WHERE cluster_id=$1 AND event_id>$2
		ORDER BY event_id
		LIMIT $3`, clusterID, after, limit+1)
	if err != nil {
		return Page{}, fmt.Errorf("list events for cluster %s: %w", clusterID, err)
	}
	defer rows.Close()

	page := Page{Events: make([]Event, 0, limit), NextAfterID: after}
	for rows.Next() {
		var event Event
		var encoded []byte
		event.ClusterID = clusterID
		if err := rows.Scan(&event.ID, &event.Type, &event.SchemaVersion, &encoded, &event.CreatedAt); err != nil {
			return Page{}, fmt.Errorf("scan event for cluster %s: %w", clusterID, err)
		}
		payload, err := decodePayload(event.Type, event.SchemaVersion, encoded)
		if err != nil {
			return Page{}, fmt.Errorf("decode event %d for cluster %s: %w", event.ID, clusterID, err)
		}
		event.Payload = payload
		event.CreatedAt = event.CreatedAt.UTC()
		if len(page.Events) == limit {
			page.HasMore = true
			break
		}
		page.Events = append(page.Events, event)
		page.NextAfterID = event.ID
	}
	if err := rows.Err(); err != nil {
		return Page{}, fmt.Errorf("iterate events for cluster %s: %w", clusterID, err)
	}
	return page, nil
}

func (s *Store) WaitAfter(ctx context.Context, clusterID domain.ClusterID, after ID, limit int, wait time.Duration) (Page, error) {
	if err := validateRead(clusterID, limit); err != nil {
		return Page{}, err
	}
	if wait < 0 || wait > MaxWait {
		return Page{}, fmt.Errorf("event wait must be between 0 and %s", MaxWait)
	}
	page, err := s.ListAfter(ctx, clusterID, after, limit)
	if err != nil || len(page.Events) > 0 || wait == 0 {
		return page, err
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	ticker := time.NewTicker(waitPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return Page{}, ctx.Err()
		case <-deadline.C:
			// A final durable read closes the race between the last poll and timeout.
			return s.ListAfter(ctx, clusterID, after, limit)
		case <-ticker.C:
			page, err := s.ListAfter(ctx, clusterID, after, limit)
			if err != nil || len(page.Events) > 0 {
				return page, err
			}
		}
	}
}

func decodePayload(eventType string, schemaVersion int, encoded []byte) (Payload, error) {
	switch {
	case eventType == CollectionUpdatedType && schemaVersion == PayloadSchemaV1:
		var payload CollectionUpdatedV1
		if err := json.Unmarshal(encoded, &payload); err != nil {
			return nil, err
		}
		if err := payload.validate(); err != nil {
			return nil, errors.New("stored payload failed validation: " + err.Error())
		}
		return payload, nil
	case eventType == SourceUpdatedType && schemaVersion == PayloadSchemaV1:
		var payload SourceUpdatedV1
		if err := json.Unmarshal(encoded, &payload); err != nil {
			return nil, err
		}
		if err := payload.validate(); err != nil {
			return nil, errors.New("stored payload failed validation: " + err.Error())
		}
		return payload, nil
	default:
		return nil, fmt.Errorf("unsupported event type %q schema version %d", eventType, schemaVersion)
	}
}
