package alertdelivery

import (
	"encoding/json"
	"time"
)

type ProductionOccurrence struct {
	ID                string     `json:"occurrence_id"`
	ClusterID         string     `json:"cluster_id"`
	EnrollmentID      string     `json:"enrollment_id"`
	SourceID          string     `json:"source_id"`
	Category          string     `json:"category"`
	Asset             string     `json:"asset"`
	IncidentID        string     `json:"incident_id"`
	Version           int64      `json:"version"`
	NextSequence      int64      `json:"next_sequence"`
	OpenedAt          time.Time  `json:"opened_at"`
	ClosedAt          *time.Time `json:"closed_at,omitempty"`
	AcknowledgedBy    string     `json:"acknowledged_by"`
	AcknowledgedAt    *time.Time `json:"acknowledged_at,omitempty"`
	MaintenanceUntil  *time.Time `json:"maintenance_until,omitempty"`
	MaintenanceBy     string     `json:"maintenance_by"`
	MaintenanceReason string     `json:"maintenance_reason"`
	EvidenceURL       string     `json:"evidence_url"`
}

type ProductionNotificationEvent struct {
	ID         string          `json:"event_id"`
	Sequence   int64           `json:"sequence"`
	Kind       string          `json:"kind"`
	At         time.Time       `json:"occurred_at"`
	Summary    string          `json:"summary"`
	EvidenceID string          `json:"evidence_id"`
	Evidence   json.RawMessage `json:"evidence"`
}
type ProductionNotificationHistory struct {
	Occurrence     ProductionOccurrence          `json:"occurrence"`
	Events         []ProductionNotificationEvent `json:"events"`
	NextAfter      int64                         `json:"next_after"`
	More           bool                          `json:"more"`
	Delivery       json.RawMessage               `json:"delivery"`
	Audit          json.RawMessage               `json:"audit"`
	NextAuditAfter int64                         `json:"next_audit_after"`
	MoreAudit      bool                          `json:"more_audit"`
}
