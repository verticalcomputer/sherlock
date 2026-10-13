package telemetry

import "time"

// Grant is an administrator-approved immutable enrollment scope. Rotation and
// revocation advance ControlRevision, never EnrollmentRevision: old owned batch
// signatures remain bound to the semantic authority that admitted them.
// Semantic inventory/source/node/gateway/version/build/pin changes require an
// explicit new enrollment ID. Gateway authentication cannot create this grant.
type Grant struct {
	ProtocolVersion     int           `json:"protocol_version"`
	EnrollmentID        string        `json:"enrollment_id"`
	EnrollmentRevision  int64         `json:"enrollment_revision"`
	ControlRevision     int64         `json:"control_revision"`
	Status              string        `json:"status"`
	ClusterID           string        `json:"cluster_id"`
	NodeID              string        `json:"node_id"`
	InventoryRevisionID string        `json:"inventory_revision_id"`
	GatewayCollectorID  string        `json:"gateway_collector_id"`
	Sources             []SourceGrant `json:"sources"`
	AgentVersion        string        `json:"agent_version"`
	BuildSHA256         string        `json:"build_sha256"`
	GatewaySPKISHA256   string        `json:"gateway_spki_sha256"`
	Keys                []NodeKey     `json:"keys"`
	// These are issued response lease bounds (at most five minutes), not a
	// restriction on historical signed batch CreatedAt. Owned replay may predate
	// a newly issued lease; current authority is always rechecked independently.
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

type SourceGrant struct {
	SourceID      string `json:"source_id"`
	SchemaVersion int    `json:"schema_version"`
	ProfileID     string `json:"profile_id"`
}

// At most two key epochs remain authorized. Routine certificate renewal keeps
// the active key. VERIFY_ONLY keys may verify already registered old sessions,
// never a new session. Rotation cannot replace a still-owned prior key epoch.
// REVOKED compromise keys reject every replay before receipt lookup.
type NodeKey struct {
	ID              string `json:"id"`
	Epoch           string `json:"epoch"`
	PublicKeyBase64 string `json:"public_key_base64"`
	State           string `json:"state"`
}

// GrantBundle is obtained only over the gateway's existing authenticated pinned
// TLS boundary. A running gateway limits it to five minutes using a monotonic
// local deadline; restart requires a new authenticated poll before admission.
// Serialized wall-clock times cannot extend local authority after a restart.
type GrantBundle struct {
	ProtocolVersion    int       `json:"protocol_version"`
	GatewayCollectorID string    `json:"gateway_collector_id"`
	FetchedAt          time.Time `json:"fetched_at"`
	LeaseExpiresAt     time.Time `json:"lease_expires_at"`
	Grants             []Grant   `json:"grants"`
}

type GatewayReceipt = Receipt

// CloudReceipt represents a committed cloud intake. GatewayReceiptID links
// responsibility transfer to the exact preceding durable local receipt.
type CloudReceipt struct {
	ProtocolVersion  int       `json:"protocol_version"`
	ID               string    `json:"id"`
	Key              BatchKey  `json:"key"`
	Digest           string    `json:"digest"`
	GatewayReceiptID string    `json:"gateway_receipt_id"`
	StoredAt         time.Time `json:"stored_at"`
	Durability       string    `json:"durability"`
	HistoryOnly      bool      `json:"history_only"`
}

// Finalization receipts acknowledge lifecycle persistence only. They do not
// certify holes as received. Retirement requires separately persisted received
// intervals/cloud receipts/explicit loss covering the terminal sequence.
type SessionReceipt struct {
	ProtocolVersion    int       `json:"protocol_version"`
	ID                 string    `json:"id"`
	ClusterID          string    `json:"cluster_id"`
	NodeID             string    `json:"node_id"`
	EnrollmentID       string    `json:"enrollment_id"`
	EnrollmentRevision int64     `json:"enrollment_revision"`
	SessionEpoch       string    `json:"session_epoch"`
	SessionID          string    `json:"session_id"`
	BootID             string    `json:"boot_id"`
	Kind               string    `json:"kind"`
	Digest             string    `json:"digest"`
	StoredAt           time.Time `json:"stored_at"`
	Durability         string    `json:"durability"`
	Retired            bool      `json:"retired"`
	Finalized          bool      `json:"finalized"`
	Covered            bool      `json:"covered"`
}

type CloudBatchEnvelope struct {
	Batch            NodeBatch `json:"batch"`
	GatewayReceiptID string    `json:"gateway_receipt_id"`
}
