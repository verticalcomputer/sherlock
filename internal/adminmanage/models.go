// Package adminmanage provides the narrow database boundary used by the
// private administrator API for cluster management and operational listings.
package adminmanage

import (
	"errors"
	"fmt"
	"io"
	"time"
)

var (
	ErrNotFound = errors.New("admin resource not found")
	ErrConflict = errors.New("admin resource conflict")
	ErrInvalid  = errors.New("invalid admin management input")
)

const (
	EventClusterUpdated         = "CLUSTER_UPDATED"
	EventClusterRemoved         = "CLUSTER_REMOVED"
	EventCredentialCreated      = "CREDENTIAL_CREATED"
	EventCredentialReplaced     = "CREDENTIAL_REPLACED"
	EventCredentialRevoked      = "CREDENTIAL_REVOKED"
	EventCredentialKeyRotated   = "CREDENTIAL_KEY_ROTATED"
	EventCredentialAttempt      = "CREDENTIAL_ATTEMPT"
	EventCredentialAdminGranted = "CREDENTIAL_ADMIN_GRANTED"
	EventCredentialAdminRevoked = "CREDENTIAL_ADMIN_REVOKED"
)

var ErrCredentialAccessDenied = errors.New("credential administrator access denied")

const (
	CredentialRejectAccessDenied = "CREDENTIAL_ACCESS_DENIED"
	CredentialRejectConflict     = "CREDENTIAL_VERSION_CONFLICT"
)

type Cluster struct {
	ID                 string
	DisplayName        string
	ExpectedCollectors []string
	CreatedAt          time.Time
	RemovedAt          *time.Time
}

// CredentialMetadata is the redacted write-only projection returned to the
// admin UI. It never contains ciphertext, nonce, key material, or plaintext
// secret fields.
type CredentialMetadata struct {
	ID         string
	ClusterID  string
	Host       string
	Purpose    string
	Username   string
	KeyVersion string
	Version    int64
	Status     string
	CreatedAt  time.Time
	RevokedAt  *time.Time
	ReplacedBy string
}

type CredentialAdminGrant struct {
	ClusterID, AccessSubject string
	GrantedAt                time.Time
	RevokedAt                *time.Time
}

// CredentialInput is accepted only by the private, authenticated admin API.
// Password values remain in memory long enough for authenticated encryption.
type CredentialInput struct {
	Host                 string
	Purpose              string
	Username             string
	SSHPassword          []byte
	SudoPassword         []byte
	ExpectedVersion      int64
	ExpectedCredentialID string
}

func (input CredentialInput) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}
func (input CredentialInput) MarshalJSON() ([]byte, error) {
	return nil, errors.New("credential input cannot be JSON encoded")
}
func (input CredentialInput) MarshalText() ([]byte, error) {
	return nil, errors.New("credential input cannot be text encoded")
}

type CredentialReference struct {
	ID        string
	ClusterID string
}

// CredentialSecrets is an alias for the trusted resolver result. Callers must
// Destroy the value as soon as the bounded reviewed operation completes.
type ResolvedCredential = CredentialSecrets

type Ticket struct {
	ID                 string
	ClusterID          string
	RuleID             string
	Title              string
	Summary            string
	Severity           string
	Status             string
	UpdatedAt          time.Time
	LastSignalAt       time.Time
	AutoStartStatus    string
	AutoStartDecision  string
	AutoStartUpdatedAt *time.Time
}

type Investigation struct {
	ID                    string
	ClusterID             string
	IncidentID            string
	Question              string
	Status                string
	EntityKind            string
	EntityIDs             []string
	AuditedTokens         int64
	AuditedCostMicrounits int64
	UpdatedAt             time.Time
}

type Operations struct {
	Repairs        RepairOverview
	Tickets        []Ticket
	Investigations []Investigation
}

// InvestigationReport is the citation-bearing internal report presented to
// authenticated administrators. Model payloads have already passed the
// durable model-IO redaction policy before they reach this projection.
type InvestigationReport struct {
	Version          int
	ID               string
	ClusterID        string
	IncidentID       string
	Question         string
	Status           string
	StopReason       string
	EntityKind       string
	EntityIDs        []string
	WindowStart      time.Time
	WindowEnd        time.Time
	SuccessCriteria  []string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	CompletedAt      *time.Time
	ModelUsage       ReportModelUsage
	Findings         []ReportFinding
	ReportSections   []ReportSection
	ReportOmissions  []ReportOmission
	PrimaryAction    *ReportActionCard
	Evidence         []ReportEvidence
	ModelCalls       []ModelCall
	ContextManifests []ContextManifest
}

type ReportActionCard struct {
	ID, Owner, Action, Urgency, Rationale, EscalationCondition string
	Targets, EvidenceIDs, BlockingGaps                         []string
}

type ContextManifest struct {
	CallKey, CallKind, EstimatorVersion, IndexVersion, FallbackState, ContextMode, CheckpointDigest                               string
	AllowanceTokens, EstimatedInputTokens, RawEstimatedInputTokens, MemoryAllowanceTokens, FixedMarginTokens, MaximumOutputTokens int64
	CalibrationFactorMillionths                                                                                                   int64
	CalibrationSampleCount, MemoryCandidateCount                                                                                  int
	SelectedMemoryIDs, SelectedEvidenceIDs                                                                                        []string
	ActualInputTokens                                                                                                             *int64
	DeltaFromVersion                                                                                                              *int
	EstimatorUnderrun                                                                                                             bool
	ExclusionReasons, SectionTokens                                                                                               string
	RetrievalLatencyMilliseconds                                                                                                  int64
	ShadowOnly                                                                                                                    bool
	CreatedAt                                                                                                                     time.Time
}

// ReportModelUsage separates the controller-admitted budget ledger from the
// provider-audit ledger. Audited usage is the billed truth even when a call's
// actual usage crosses the admitted ceiling and cannot be charged to budget.
type ReportModelUsage struct {
	MaxTokens, AdmittedTokens, AuditedTokens                         int64
	MaxCostMicrounits, AdmittedCostMicrounits, AuditedCostMicrounits int64
}

type ReportEvidence struct {
	ID            string
	Kind          string
	Status        string
	ExactScope    string
	ObservedStart time.Time
	ObservedEnd   time.Time
	RecordedAt    time.Time
}

type ModelCall struct {
	ID, Kind, Provider, Model, ModelConfigVersion, PromptSchemaVersion, ToolSchemaVersion string
	InputTokens, OutputTokens, CostMicrounits, LatencyMilliseconds                        int64
	Outcome, ReasonCode                                                                   string
	OccurredAt                                                                            time.Time
	Input, Output                                                                         ModelPayload
}

type ModelPayload struct {
	EvidenceID   string
	Availability string
	MediaType    string
	Content      string
}

// ReportSection is synthesis narrative that is not a per-entity claim: the
// timeline, what remains unknown, and how far the investigation reached.
type ReportSection struct {
	ID, Kind, Statement string
	Ordinal             int
	ObservedAt          *time.Time
	EvidenceIDs         []string
}

// ReportOmission states what the report left out and why, so a reader can see
// that it is a subset of the model's answer rather than the whole of it.
type ReportOmission struct {
	Kind, Reason string
	Count        int
}

type ReportFinding struct {
	ID                 string
	Kind               string
	Statement          string
	EntityIDs          []string
	Severity           string
	Confidence         *float64
	EvidenceIDs        []string
	CounterEvidenceIDs []string
}

// MutationAudit is safe, bounded metadata recorded atomically with a cluster
// mutation. It must never contain credentials, request bodies, or error text.
type MutationAudit struct {
	EventID            string
	EventKind          string
	ReasonCode         string
	SessionFingerprint []byte
	RequestID          string
	OccurredAt         time.Time
	ActorSubject       string
	ClusterID          string
	CredentialID       string
	CredentialVersion  int64
}

// RepairOverview is a read-only M15 projection. Gate enablement is not service health.
type RepairOverview struct {
	Available           bool
	GlobalEnabled       bool
	ActiveRequests      int64
	PendingVerification int64
	Succeeded           int64
	Contained           int64
	Cancelled           int64
	RolledBack          int64
	Decisions           []RepairDecision
}
type RepairDecision struct {
	Code  string
	Count int64
}
