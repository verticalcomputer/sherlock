// Package nodetelemetry runs the synthetic resident telemetry qualification
// source. It has no command, SSH, hardware-source or cloud credential interface.
package nodetelemetry

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetryjournal"
)

var (
	ErrInvalid  = errors.New("node telemetry configuration invalid")
	ErrState    = errors.New("node telemetry durable state unavailable")
	ErrCapacity = errors.New("node telemetry capacity unavailable")
	ErrClock    = errors.New("node telemetry clock unavailable")
	ErrRunning  = errors.New("node telemetry runtime active")
	ErrBusy     = errors.New("node telemetry collection deferred during transfer")
)

// LocalScope is explicit local signing/retention configuration. It is not a
// leased cloud grant: gateway and cloud independently validate current authority.
type LocalScope struct {
	ClusterID           string              `json:"cluster_id"`
	NodeID              string              `json:"node_id"`
	EnrollmentID        string              `json:"enrollment_id"`
	InventoryRevisionID string              `json:"inventory_revision_id"`
	SourceIDs           []string            `json:"source_ids"`
	SourceProfiles      map[string]string   `json:"source_profiles,omitempty"`
	AgentVersion        string              `json:"agent_version"`
	BuildSHA256         string              `json:"build_sha256"`
	GatewaySPKISHA256   string              `json:"gateway_spki_sha256"`
	Keys                []telemetry.NodeKey `json:"keys"`
}

type LinuxCollector interface {
	Collect(context.Context, string, string, string, string, string, time.Time) (telemetry.SourceFrame, error)
}

type Gateway interface {
	RegisterSession(context.Context, telemetry.SessionMessage) (telemetry.SessionReceipt, error)
	SubmitBatch(context.Context, []byte) (telemetry.Receipt, error)
}

// RetirementGateway is additive. Old peers never authorize optimistic local
// pruning; they retain the original bounded spool/backpressure behavior.
type RetirementGateway interface {
	RetirementCapabilities(context.Context) (telemetry.RetirementCapabilities, error)
	ReleaseOwnership(context.Context, telemetry.ReleaseEnvelope) (telemetry.GatewayRetirementReceipt, error)
	CompleteNodeRelease(context.Context, telemetry.NodeReleaseCompletion) (telemetry.NodeCompletionReceipt, error)
}

type Config struct {
	Root         string
	Scope        LocalScope
	SigningKeyID string
	SigningKey   ed25519.PrivateKey
	Gateway      Gateway
	Interval     time.Duration
	Now          func() time.Time
	BootID       func() (string, error)
	// LinuxSources implements the closed Linux profiles; nil forbids their startup.
	LinuxSources LinuxCollector
	// Report receives fixed safe failure codes, never source bodies or key data.
	Report func(error)
	limits *telemetryjournal.Limits
	fault  func(string) error
}

type Runtime struct {
	mu                sync.Mutex
	drainMu           sync.Mutex
	config            Config
	q                 *telemetryjournal.Queue
	state             allocator
	boot              string
	running, closed   bool
	draining          bool
	collectionPending bool
	turn              uint64
	limiter           tokenBucket
	maxAge            time.Duration
	retirementUntil   time.Time
	retirementTurn    uint64
}

type sessionState struct {
	Open            telemetry.SessionMessage  `json:"open"`
	Final           *telemetry.SessionMessage `json:"final,omitempty"`
	LastAllocated   string                    `json:"last_allocated"`
	OpenAck         *telemetry.SessionReceipt `json:"open_ack,omitempty"`
	FinalAck        *telemetry.SessionReceipt `json:"final_ack,omitempty"`
	ReleasedThrough string                    `json:"released_through"`
	EmptyReleased   bool                      `json:"empty_released"`
}
type pendingAllocation struct {
	Key telemetry.BatchKey `json:"key"`
}
type carrierProof struct {
	Key     telemetry.BatchKey `json:"key"`
	Digest  string             `json:"digest"`
	Receipt telemetry.Receipt  `json:"receipt"`
}
type signedGap struct {
	Key          telemetry.BatchKey `json:"key"`
	SourceIDs    []string           `json:"source_ids"`
	Reason       string             `json:"reason"`
	SigningKeyID string             `json:"signing_key_id"`
	Digest       string             `json:"digest"`
	Signature    string             `json:"signature"`
	Carrier      *carrierProof      `json:"carrier,omitempty"`
}
type allocator struct {
	Version       int                `json:"version"`
	ScopeDigest   string             `json:"scope_digest"`
	BaseEpoch     uint64             `json:"base_epoch"`
	Sessions      []sessionState     `json:"sessions"`
	Pending       *pendingAllocation `json:"pending,omitempty"`
	Gaps          []signedGap        `json:"gaps"`
	LossCursor    uint64             `json:"loss_cursor"`
	LastCreatedAt time.Time          `json:"last_created_at"`
	Checksum      string             `json:"checksum"`
}
