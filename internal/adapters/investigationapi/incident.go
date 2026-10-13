package investigationapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	publicapi "github.com/verticalcomputer/sherlock/internal/api"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type incidentPayload struct {
	Summary     string   `json:"summary"`
	TargetIDs   []string `json:"target_ids"`
	EvidenceIDs []string `json:"evidence_ids"`
}

func (service *Service) CreateIncident(ctx context.Context, input publicapi.CreateIncidentInput) (publicapi.IncidentResource, bool, error) {
	if err := validateIncidentInput(input); err != nil {
		return publicapi.IncidentResource{}, false, err
	}
	now := service.clock.Now().UTC()
	id := stableID("incident-", input.ClusterID, input.IdempotencyKey)
	createdPayload := incidentPayload{Summary: input.Summary, TargetIDs: input.TargetIDs, EvidenceIDs: input.EvidenceIDs}
	payload, err := json.Marshal(createdPayload)
	if err != nil {
		return publicapi.IncidentResource{}, false, mapError(fmt.Errorf("encode incident request: %w", err))
	}
	canonical, err := json.Marshal(struct {
		ClusterID    domain.ClusterID `json:"cluster_id"`
		ActorID      string           `json:"actor_id"`
		Title        string           `json:"title"`
		Severity     string           `json:"severity"`
		IncidentData incidentPayload  `json:"incident_data"`
	}{ClusterID: input.ClusterID, ActorID: input.ActorID, Title: input.Title, Severity: input.Severity, IncidentData: createdPayload})
	if err != nil {
		return publicapi.IncidentResource{}, false, mapError(fmt.Errorf("encode incident idempotency request: %w", err))
	}
	requestHash := domain.ChecksumSHA256(canonical)
	tx, err := service.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return publicapi.IncidentResource{}, false, mapError(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var priorID string
	var priorHash []byte
	err = tx.QueryRow(ctx, `SELECT resource_id,request_hash FROM investigation_idempotency_records WHERE cluster_id=$1 AND operation='CREATE_INCIDENT' AND idempotency_key=$2 AND status='COMPLETED'`, input.ClusterID, input.IdempotencyKey).Scan(&priorID, &priorHash)
	if err == nil {
		if priorID != id || !bytes.Equal(priorHash, requestHash[:]) {
			return publicapi.IncidentResource{}, false, publicapi.ErrInvestigationConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return publicapi.IncidentResource{}, false, mapError(err)
		}
		item, found, loadErr := service.GetIncident(ctx, id)
		if loadErr != nil || !found {
			return publicapi.IncidentResource{}, false, mapError(loadErr)
		}
		return item, true, nil
	}
	if err != pgx.ErrNoRows {
		return publicapi.IncidentResource{}, false, mapError(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO incidents (incident_id,cluster_id,title,summary,severity,status,created_by,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,'OPEN',$6,$7,$7)`, id, input.ClusterID, input.Title, input.Summary, input.Severity, input.ActorID, now)
	if err != nil {
		return publicapi.IncidentResource{}, false, mapError(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO incident_events (cluster_id,incident_id,sequence,event_key,event_type,actor_id,incident_version,payload,occurred_at) VALUES ($1,$2,1,$3,'CREATED',$4,1,$5,$6)`, input.ClusterID, id, "created-"+id, input.ActorID, payload, now)
	if err != nil {
		return publicapi.IncidentResource{}, false, mapError(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO investigation_idempotency_records (cluster_id,operation,idempotency_key,request_hash,status,resource_kind,resource_id,response_code,created_at,completed_at) VALUES ($1,'CREATE_INCIDENT',$2,$3,'COMPLETED','INCIDENT',$4,201,$5,$5)`, input.ClusterID, input.IdempotencyKey, requestHash[:], id, now)
	if err != nil {
		return publicapi.IncidentResource{}, false, mapError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return publicapi.IncidentResource{}, false, mapError(err)
	}
	item, found, err := service.GetIncident(ctx, id)
	if err != nil || !found {
		return publicapi.IncidentResource{}, false, mapError(err)
	}
	return item, false, nil
}

func (service *Service) GetIncident(ctx context.Context, id string) (publicapi.IncidentResource, bool, error) {
	item, err := scanIncident(service.pool.QueryRow(ctx, incidentSelect+` WHERE i.incident_id=$1`, id))
	if err == pgx.ErrNoRows {
		return publicapi.IncidentResource{}, false, nil
	}
	if err != nil {
		return publicapi.IncidentResource{}, false, mapError(err)
	}
	return item, true, nil
}

const incidentSelect = `SELECT i.incident_id,i.cluster_id,i.title,i.summary,i.severity,i.status,i.created_by,i.created_at,i.updated_at,i.version,COALESCE(e.payload,'{}'::jsonb),COALESCE((SELECT array_agg(v.investigation_id ORDER BY v.created_at,v.investigation_id) FROM investigations v WHERE v.incident_id=i.incident_id),ARRAY[]::text[]),COALESCE((SELECT array_agg(x.evidence_id ORDER BY x.attached_at,x.evidence_id) FROM incident_evidence x WHERE x.incident_id=i.incident_id),ARRAY[]::text[]) FROM incidents i LEFT JOIN incident_events e ON e.incident_id=i.incident_id AND e.event_type='CREATED'`

type rowScanner interface{ Scan(...any) error }

func scanIncident(row rowScanner) (publicapi.IncidentResource, error) {
	var item publicapi.IncidentResource
	var payload []byte
	var attachedEvidence []string
	if err := row.Scan(&item.IncidentID, &item.ClusterID, &item.Title, &item.Summary, &item.Severity, &item.Status, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt, &item.Version, &payload, &item.InvestigationIDs, &attachedEvidence); err != nil {
		return publicapi.IncidentResource{}, err
	}
	var created incidentPayload
	if err := json.Unmarshal(payload, &created); err != nil {
		return publicapi.IncidentResource{}, err
	}
	item.TargetIDs, item.EvidenceIDs = created.TargetIDs, created.EvidenceIDs
	if len(attachedEvidence) > 0 {
		item.EvidenceIDs = attachedEvidence
	}
	return item, nil
}

func validateIncidentInput(input publicapi.CreateIncidentInput) error {
	if input.ClusterID == "" || input.ActorID == "" || input.IdempotencyKey == "" || len(input.Title) < 1 || len(input.Title) > 256 || len(input.Summary) > 4096 || len(input.TargetIDs) > 256 || len(input.EvidenceIDs) > 1024 {
		return publicapi.ErrInvestigationInvalid
	}
	for _, values := range [][]string{input.TargetIDs, input.EvidenceIDs} {
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			if value == "" || len(value) > 128 {
				return publicapi.ErrInvestigationInvalid
			}
			if _, exists := seen[value]; exists {
				return publicapi.ErrInvestigationInvalid
			}
			seen[value] = struct{}{}
		}
	}
	return nil
}

type incidentCursor struct {
	UpdatedAt time.Time `json:"updated_at"`
	ID        string    `json:"id"`
}

func (service *Service) ListIncidents(ctx context.Context, clusterID domain.ClusterID, options publicapi.IncidentListOptions) ([]publicapi.IncidentResource, string, error) {
	limit := options.PageSize
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 200 {
		return nil, "", publicapi.ErrInvestigationInvalid
	}
	cursor := incidentCursor{UpdatedAt: time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC), ID: "\U0010ffff"}
	if options.PageToken != "" {
		raw, err := base64.RawURLEncoding.DecodeString(options.PageToken)
		if err != nil || json.Unmarshal(raw, &cursor) != nil || cursor.UpdatedAt.IsZero() || cursor.ID == "" {
			return nil, "", publicapi.ErrInvestigationInvalid
		}
	}
	rows, err := service.pool.Query(ctx, incidentSelect+` WHERE i.cluster_id=$1 AND ($2='' OR i.status=$2) AND ($3='' OR i.severity=$3) AND (i.updated_at,i.incident_id)<($4,$5) ORDER BY i.updated_at DESC,i.incident_id DESC LIMIT $6`, clusterID, options.Status, options.Severity, cursor.UpdatedAt, cursor.ID, limit+1)
	if err != nil {
		return nil, "", mapError(err)
	}
	defer rows.Close()
	var items []publicapi.IncidentResource
	for rows.Next() {
		item, err := scanIncident(rows)
		if err != nil {
			return nil, "", mapError(err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapError(err)
	}
	hasNext := len(items) > limit
	if hasNext {
		items = items[:limit]
	}
	if !hasNext || len(items) == 0 {
		return items, "", nil
	}
	last := items[len(items)-1]
	raw, err := json.Marshal(incidentCursor{UpdatedAt: last.UpdatedAt, ID: last.IncidentID})
	if err != nil {
		return nil, "", mapError(err)
	}
	return items, base64.RawURLEncoding.EncodeToString(raw), nil
}
