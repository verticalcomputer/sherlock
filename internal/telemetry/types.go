// Package telemetry defines unsolicited resident telemetry independently from
// collector work leases. Its v1 source profile is synthetic; it grants no
// hardware-health, workload, diagnostic, command or repair authority.
package telemetry

import "time"

const (
	ProtocolVersion = 1
	MaxBatchBytes   = 1 << 20
	// Reserve room for the cloud envelope and its bounded gateway receipt ID.
	MaxNodeBatchBytes = MaxBatchBytes - 512
	MaxRecords        = 4096
	MaxSources        = 16
	MaxLossRanges     = 256
)

type BatchKey struct {
	ClusterID    string `json:"cluster_id"`
	NodeID       string `json:"node_id"`
	EnrollmentID string `json:"enrollment_id"`
	SessionEpoch string `json:"session_epoch"`
	SessionID    string `json:"session_id"`
	Sequence     string `json:"sequence"`
}

// NodeBatch deliberately contains no work ID, lease, command, source URL,
// arbitrary labels or credential. Its digest excludes only Digest/Signature.
type NodeBatch struct {
	ProtocolVersion     int           `json:"protocol_version"`
	Key                 BatchKey      `json:"key"`
	EnrollmentRevision  int64         `json:"enrollment_revision"`
	InventoryRevisionID string        `json:"inventory_revision_id"`
	BootID              string        `json:"boot_id"`
	SigningKeyID        string        `json:"signing_key_id"`
	AgentVersion        string        `json:"agent_version"`
	BuildSHA256         string        `json:"build_sha256"`
	CreatedAt           time.Time     `json:"created_at"`
	Sources             []SourceFrame `json:"sources"`
	Digest              string        `json:"digest"`
	Signature           string        `json:"signature"`
}

type SourceFrame struct {
	SourceID       string         `json:"source_id"`
	SchemaVersion  int            `json:"schema_version"`
	AdapterVersion string         `json:"adapter_version"`
	ProfileID      string         `json:"profile_id"`
	StartedAt      time.Time      `json:"started_at"`
	CompletedAt    time.Time      `json:"completed_at"`
	Status         string         `json:"status"`
	Coverage       Coverage       `json:"coverage"`
	Fields         []FieldSupport `json:"fields"`
	Records        []Record       `json:"records"`
	Loss           []LossRange    `json:"loss"`
}

type Coverage struct {
	Expected int64 `json:"expected"`
	Returned int64 `json:"returned"`
	Complete bool  `json:"complete"`
}

type FieldSupport struct {
	EntityKey string `json:"entity_key"`
	Metric    string `json:"metric"`
	State     string `json:"state"`
	Reason    string `json:"reason"`
}

// Scalar keeps exact unsigned counters out of floating point. Each kind has
// exactly one populated value. Enum values are source-schema-owned constants.
type Scalar struct {
	Kind     string   `json:"kind"`
	Float    *float64 `json:"float,omitempty"`
	Unsigned string   `json:"unsigned,omitempty"`
	Boolean  *bool    `json:"boolean,omitempty"`
	Enum     string   `json:"enum,omitempty"`
}

type Record struct {
	ID            string    `json:"id"`
	EntityKey     string    `json:"entity_key"`
	Metric        string    `json:"metric"`
	Unit          string    `json:"unit"`
	Kind          string    `json:"kind"`
	Reset         string    `json:"reset"`
	ResetObserved bool      `json:"reset_observed"`
	ObservedAt    time.Time `json:"observed_at"`
	CollectedAt   time.Time `json:"collected_at"`
	Value         Scalar    `json:"value"`
}

type LossRange struct {
	ID string `json:"id"`
	// AffectedKey names the original session and first lost sequence. It may
	// precede the containing batch's current session after a reboot.
	AffectedKey     BatchKey   `json:"affected_key"`
	ThroughSequence string     `json:"through_sequence"`
	FromAt          *time.Time `json:"from_at"`
	ThroughAt       *time.Time `json:"through_at"`
	Reason          string     `json:"reason"`
	CountKnown      bool       `json:"count_known"`
	Count           string     `json:"count,omitempty"`
}

// GatewayDurability means local ownership only. CloudDurability is a separate
// authenticated-store commit; neither means physical source health.
type Receipt struct {
	ProtocolVersion int       `json:"protocol_version"`
	ID              string    `json:"id"`
	Key             BatchKey  `json:"key"`
	Digest          string    `json:"digest"`
	StoredAt        time.Time `json:"stored_at"`
	Durability      string    `json:"durability"`
}

// Session lifecycle messages are signed node facts, never commands. A new boot
// uses exactly the next durably allocated epoch. Restart in the same boot keeps
// its session. Finalize declares the last allocated sequence, not an assertion
// that missing batches were received; accepted/loss ranges must cover it.
type SessionMessage struct {
	ProtocolVersion       int           `json:"protocol_version"`
	Kind                  string        `json:"kind"`
	ClusterID             string        `json:"cluster_id"`
	NodeID                string        `json:"node_id"`
	EnrollmentID          string        `json:"enrollment_id"`
	EnrollmentRevision    int64         `json:"enrollment_revision"`
	SessionEpoch          string        `json:"session_epoch"`
	SessionID             string        `json:"session_id"`
	BootID                string        `json:"boot_id"`
	SigningKeyID          string        `json:"signing_key_id"`
	LastAllocatedSequence string        `json:"last_allocated_sequence,omitempty"`
	Loss                  []SessionLoss `json:"loss,omitempty"`
	CreatedAt             time.Time     `json:"created_at"`
	Digest                string        `json:"digest"`
	Signature             string        `json:"signature"`
}

type SessionLoss struct {
	SourceID string    `json:"source_id"`
	Range    LossRange `json:"range"`
}
