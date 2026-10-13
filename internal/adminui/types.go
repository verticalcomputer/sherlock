package adminui

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/networkmonitor"
)

var ErrRecordNotFound = errors.New("admin record not found")
var ErrHumanAccessDenied = errors.New("human cluster membership was not accepted")

// HumanSessionChecker asks the private API to recheck the verified identity's
// active cluster membership before serving any dashboard request.
type HumanSessionChecker interface {
	CheckHumanSession(context.Context) error
}

// CredentialInventoryDiscoveryOperation mirrors the reviewed domain constant
// so templates and projections name the same operation the store does.
const CredentialInventoryDiscoveryOperation = domain.CredentialInventoryDiscoveryOperation

// DataProvider is the UI's server-to-server administrative API boundary.
// Implementations must return redacted records and perform mutations through
// the private API; the dashboard process must never connect to the database.
type DataProvider interface {
	ListClusters(context.Context) ([]ClusterRecord, error)
	GetCluster(context.Context, string) (ClusterRecord, error)
	GetClusterSummary(context.Context, string) (Cluster, error)
	UpdateCluster(context.Context, string, ClusterUpdate, MutationContext) error
	RemoveCluster(context.Context, string, MutationContext) error
	LoadOperations(context.Context) (Operations, error)
	LoadClusterOperations(context.Context, string) (Operations, error)
	LoadInvestigationReport(context.Context, string) (InvestigationReport, error)
	StartInvestigation(context.Context, string, InvestigationStart, MutationContext) (InvestigationStartResult, error)
}

// CredentialProvider is optional so deployments without an external keyring
// remain read-only and credential onboarding stays disabled by default.
type CredentialProvider interface {
	ListCredentialMetadata(context.Context, string, string) ([]CredentialMetadata, error)
	PutCredential(context.Context, string, string, CredentialInput, MutationContext) (CredentialMetadata, error)
	RevokeCredential(context.Context, string, string, int64, MutationContext) error
}

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

type CredentialInput struct {
	Host                 string
	Purpose              string
	Username             string
	SSHPassword          string
	SudoPassword         string
	ExpectedVersion      int64
	ExpectedCredentialID string
}

// ClusterRecord is the editable administrative representation of a cluster.
// Removal is a soft decommission: it revokes cluster access and preserves the
// durable evidence and audit history.
type ClusterRecord struct {
	ID                 string
	DisplayName        string
	ExpectedCollectors []string
	State              OperationalState
	CreatedAt          time.Time
	RemovedAt          *time.Time
	LastSeenAt         time.Time
	Description        string
}

type ClusterUpdate struct {
	DisplayName        string
	ExpectedCollectors []string
}

type MutationContext struct {
	SessionFingerprint []byte
	RequestID          string
	OccurredAt         time.Time
	ActorSubject       string
}

// InvestigationStart is the deliberately bounded operator input accepted by
// the private admin surface. Privileged calls are not exposed here: an admin
// can request reviewed reads and diagnostics, but cannot grant privileged
// execution from this form.
type InvestigationStart struct {
	Purpose            string
	IncidentID         string
	Question           string
	EntityKind         string
	EntityIDs          []string
	WindowStart        time.Time
	WindowEnd          time.Time
	SuccessCriteria    []string
	MaxDecisions       int
	MaxToolCalls       int
	MaxDiagnosticCalls int
	MaxFanOut          int
	MaxModelTokens     int64
	MaxCostMicrounits  int64
	Deadline           time.Time
	IdempotencyKey     string
}

type InvestigationStartResult struct {
	ID       string
	Status   string
	Replayed bool
}

type Operations struct {
	Repairs        RepairOverview
	GeneratedAt    time.Time
	Tickets        []Ticket
	Investigations []Investigation
}

type Ticket struct {
	ID                   string
	ClusterID            string
	RuleID               string
	Title                string
	Summary              string
	Severity             string
	Status               string
	UpdatedAt            time.Time
	LastSignalAt         time.Time
	AutoStartStatus      string
	AutoStartDecision    string
	AutoStartUpdatedAt   *time.Time
	RelatedIncidentCount int
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

// InvestigationReport is an audited, read-only projection of durable state,
// evidence, and already-redacted model input/output payloads.
type InvestigationReport struct {
	Shared                                                              bool
	Version                                                             int
	ID, ClusterID, IncidentID, Question, Status, StopReason, EntityKind string
	EntityIDs                                                           []string
	WindowStart, WindowEnd, CreatedAt, UpdatedAt                        time.Time
	CompletedAt                                                         *time.Time
	ModelUsage                                                          ReportModelUsage
	SuccessCriteria                                                     []string
	Findings                                                            []ReportFinding
	ReportSections                                                      []ReportSection
	ReportOmissions                                                     []ReportOmission
	PrimaryAction                                                       *ReportActionCard
	Evidence                                                            []ReportEvidence
	ModelCalls                                                          []ModelCall
	ContextManifests                                                    []ContextManifest
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

type ReportModelUsage struct {
	MaxTokens, AdmittedTokens, AuditedTokens                         int64
	MaxCostMicrounits, AdmittedCostMicrounits, AuditedCostMicrounits int64
}

type ReportEvidence struct {
	ID, Kind, Status, ExactScope           string
	ObservedStart, ObservedEnd, RecordedAt time.Time
}

type ModelCall struct {
	ID, Kind, Provider, Model, ModelConfigVersion, PromptSchemaVersion, ToolSchemaVersion string
	InputTokens, OutputTokens, CostMicrounits, LatencyMilliseconds                        int64
	Outcome, ReasonCode                                                                   string
	OccurredAt                                                                            time.Time
	Input, Output                                                                         ModelPayload
}

type ModelPayload struct {
	EvidenceID, Availability, MediaType, Content string
}

// ReportSection is synthesis narrative that is not a per-entity claim: when
// things happened, what the run still does not know, and how far it reached.
type ReportSection struct {
	ID, Kind, Statement string
	Ordinal             int
	ObservedAt          *time.Time
	EvidenceIDs         []string
}

// ReportOmission states what this report left out and why.
type ReportOmission struct {
	Kind, Reason string
	Count        int
}

type ReportFinding struct {
	ID, Kind, Statement, Severity string
	EntityIDs                     []string
	Confidence                    *float64
	EvidenceIDs                   []string
	CounterEvidenceIDs            []string
}

// OperationalState is an explicit evidence state. Only StateHealthy is
// presented as healthy; missing, stale, partial, and unavailable data remain
// visibly degraded.
type OperationalState string

const (
	StateHealthy     OperationalState = "HEALTHY"
	StateDegraded    OperationalState = "DEGRADED"
	StatePartial     OperationalState = "PARTIAL"
	StateStale       OperationalState = "STALE"
	StateUnavailable OperationalState = "UNAVAILABLE"
	StateNoData      OperationalState = "NO_DATA"
)

type Dashboard struct {
	GeneratedAt time.Time
	State       OperationalState
	Summary     string
	Metrics     []Metric
	Clusters    []Cluster
	Activity    []Activity
}

type Metric struct {
	Label       string
	Value       string
	Detail      string
	Explanation string
	State       OperationalState
}

type Cluster struct {
	Health                  application.ClusterHealthView
	ID                      string
	Name                    string
	State                   OperationalState
	EvidenceExpected        int64
	EvidenceCovered         int64
	LastSeenAt              time.Time
	Description             string
	Dimensions              []Metric
	MissingCollectorNames   []string
	MissingCollectorLabels  []string
	ExcludedCollectorLabels []string
	ExpectedCollectorNames  []string
	SourceGapLabels         []string
	OnDemandSourceLabels    []string
	EvidenceStreams         []EvidenceStreamHealth
	EvidenceHistory         EvidenceHistory
	Network                 networkmonitor.Summary
	SlurmOperations         []SlurmOperationStatus
	Resources               ResourceSummary
}

type SlurmOperationStatus struct {
	SourceID, Operation, Status string
	Fresh                       bool
	LastCompletedAt             *time.Time
}

type EvidenceStreamHealth struct {
	SourceID, Operation, Scope, Status, RunID, FailureCode, SafeFailureReason string
	Condition, RecommendedAction                                              string
	State                                                                     OperationalState
	LatestAttempt                                                             time.Time
	ExpectedTargets, CoveredTargets, MissingTargets                           []string
	SeriesExpected, SeriesReturned                                            *int
}

type EvidenceHistory struct {
	Total, Complete, Partial, NoData, Unavailable, Superseded int64
}

type ResourceSummary struct {
	Truncated             bool
	State                 OperationalState
	ObservedNodes         int64
	ObservedGPUs          int64
	GPUUtilizationPercent *float64
	GPUUtilizationSamples int64
	CPUUtilizationPercent *float64
	CPUUtilizationSamples int64
	LastObservedAt        *time.Time
}

type Activity struct {
	OccurredAt time.Time
	Kind       string
	Summary    string
	State      OperationalState
}

type EventKind string

const (
	EventAuthentication  EventKind = "AUTHENTICATION"
	EventSessionStarted  EventKind = "SESSION_STARTED"
	EventSessionEnded    EventKind = "SESSION_ENDED"
	EventSessionExpired  EventKind = "SESSION_EXPIRED"
	EventDashboardViewed EventKind = "DASHBOARD_VIEWED"
	EventClusterUpdated  EventKind = "CLUSTER_UPDATED"
	EventClusterRemoved  EventKind = "CLUSTER_REMOVED"
)

type EventOutcome string

const (
	OutcomeSucceeded EventOutcome = "SUCCEEDED"
	OutcomeRejected  EventOutcome = "REJECTED"
)

// AuditEvent contains no Cloudflare Access JWT. When present,
// SessionFingerprint is a domain-separated SHA-256 digest of the verified
// application token.
type AuditEvent struct {
	Kind               EventKind
	Outcome            EventOutcome
	ReasonCode         string
	SessionFingerprint []byte
	RequestID          string
	OccurredAt         time.Time
}

// Auditor persists safe security events. Successful authentication and reads
// fail closed when their audit record cannot be delivered.
type Auditor interface {
	RecordAdminEvent(context.Context, AuditEvent) error
}

// ErrorReporter receives a sanitized audit-delivery failure. The underlying
// backend error is deliberately not passed through this HTTP boundary.
type ErrorReporter interface {
	ReportAdminError(context.Context, AuditDeliveryError)
}

type AuditDeliveryError struct {
	Kind    EventKind
	Outcome EventOutcome
}

func (failure AuditDeliveryError) Error() string {
	return "admin audit delivery failed for " + string(failure.Kind) + " (" + string(failure.Outcome) + ")"
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

// CredentialAccessTestProvider is optional and separate from
// CredentialProvider so "Test BCM access" is only offered when the private
// API exposes it. Results are redacted codes, counts and timing only.
type CredentialAccessTestProvider interface {
	ListCredentialAccessTests(context.Context, string, string) ([]CredentialAccessTest, error)
	RequestCredentialAccessTest(context.Context, string, string, string, int64, MutationContext) (CredentialAccessTest, error)
	RequestCredentialInventoryDiscovery(context.Context, string, string, string, int64, MutationContext) (CredentialAccessTest, error)
	CancelCredentialAccessTest(context.Context, string, string, string, MutationContext) error
}

// CredentialAccessDevice is one sanitized row of a retained BCM device
// listing. It is shown only for a succeeded inventory discovery.
type CredentialAccessDevice struct {
	Type     string
	Hostname string
	Category string
	Status   string
}

// CredentialInventoryDiscovery is the newest retained listing for a cluster.
type CredentialInventoryDiscovery struct {
	TestID            string
	ClusterID         string
	CredentialID      string
	CredentialVersion int64
	Host              string
	BCMVersion        string
	CompletedAt       time.Time
	CredentialCurrent bool
	Devices           []CredentialAccessDevice
}

// CredentialAccessTest is the dashboard projection of one durable test.
// CredentialCurrent is false once the tested credential version was replaced
// or revoked, so an older success is presented as stale rather than current.
type CredentialAccessTest struct {
	ID                string
	ClusterID         string
	CredentialID      string
	CredentialVersion int64
	Host              string
	Purpose           string
	Username          string
	Operation         string
	Status            string
	RequestedBy       string
	RequestedAt       time.Time
	Deadline          time.Time
	Attempt           int
	CollectorID       string
	LeaseExpiresAt    *time.Time
	OutcomeCode       string
	OutcomeSummary    string
	BCMVersion        string
	DevicesListed     int
	CompletedAt       *time.Time
	CancelledBy       string
	CredentialCurrent bool
	CredentialStatus  string
	Devices           []CredentialAccessDevice
}

// Pending reports whether the test has not reached a terminal state.
func (test CredentialAccessTest) Pending() bool {
	switch test.Status {
	case "REQUESTED", "CLAIMED", "RUNNING":
		return true
	}
	return false
}

// Verified reports a successful test bound to the still-current credential.
// It is only ever true for the access-test operation: an inventory discovery
// lists devices, it does not verify anything, and the template must never
// present it as verification.
func (test CredentialAccessTest) Verified() bool {
	return test.Status == "SUCCEEDED" && test.CredentialCurrent && test.Operation != CredentialInventoryDiscoveryOperation
}

// Listed reports a succeeded inventory discovery bound to the still-current
// credential. It is deliberately named for what it proves: devices were
// listed, not that the credential was verified.
func (test CredentialAccessTest) Listed() bool {
	return test.Status == "SUCCEEDED" && test.CredentialCurrent && test.Operation == CredentialInventoryDiscoveryOperation
}

// DeviceCount is the number of retained rows for a discovery.
func (test CredentialAccessTest) DeviceCount() int { return len(test.Devices) }

// DeviceTypeCounts summarizes the retained listing by device type, in
// descending count order then alphabetically, so the page is stable.
func (test CredentialAccessTest) DeviceTypeCounts() []CredentialDeviceTypeCount {
	counts := map[string]int{}
	for _, device := range test.Devices {
		counts[device.Type]++
	}
	summary := make([]CredentialDeviceTypeCount, 0, len(counts))
	for deviceType, count := range counts {
		summary = append(summary, CredentialDeviceTypeCount{Type: deviceType, Count: count})
	}
	sort.Slice(summary, func(i, j int) bool {
		if summary[i].Count != summary[j].Count {
			return summary[i].Count > summary[j].Count
		}
		return summary[i].Type < summary[j].Type
	})
	return summary
}

// CredentialDeviceTypeCount is one row of the per-type summary.
type CredentialDeviceTypeCount struct {
	Type  string
	Count int
}

// InvestigationCanceller preserves the existing controller's version fence.
type InvestigationCanceller interface {
	CancelInvestigation(context.Context, string, int, string, MutationContext) error
}
