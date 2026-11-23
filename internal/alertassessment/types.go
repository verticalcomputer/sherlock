// Package alertassessment implements the bounded, category-independent assessment
// contract. It has no production notification or collection authority.
package alertassessment

import (
	"context"
	"encoding/json"
	"time"
)

const (
	ContractVersion  int64 = 1
	MaxFacts               = 1024
	MaxInputBytes          = 16 << 20
	MaxPayloadBytes        = 16 << 10
	MaxDetailsBytes        = 4 << 10
	MaxProposalBytes       = 64 << 10
)

var v1Budgets = [...]int64{0, 15000, 30000, 60000, 120000}

// Budgets provides the v1 comparison arms to callers. The host validates
// requests and configuration against its own immutable values.
var Budgets = v1Budgets

type Payload struct {
	Category string          `json:"category"`
	Kind     string          `json:"kind"`
	Schema   int64           `json:"schema"`
	Hash     string          `json:"hash"`
	Body     json.RawMessage `json:"body"`
}
type Metric struct {
	Metric         string `json:"metric"`
	Unit           string `json:"unit"`
	Required       bool   `json:"required"`
	HistorySeconds int64  `json:"history_seconds"`
}
type Outcome struct {
	Code          string `json:"code"`
	Purpose       string `json:"purpose"`
	Phase         string `json:"phase"`
	Action        string `json:"action"`
	EvidenceClass string `json:"evidence_class"`
}
type Update struct {
	Code          string `json:"code"`
	Action        string `json:"action"`
	EvidenceClass string `json:"evidence_class"`
}
type PayloadLimits struct {
	Policy    int64 `json:"policy"`
	Tracker   int64 `json:"tracker"`
	Candidate int64 `json:"candidate"`
	Details   int64 `json:"details"`
}
type Descriptor struct {
	Category        string        `json:"category"`
	Contract        int64         `json:"contract"`
	Implementation  int64         `json:"implementation"`
	PolicySchema    int64         `json:"policy_schema"`
	TrackerSchema   int64         `json:"tracker_schema"`
	CandidateSchema int64         `json:"candidate_schema"`
	DetailsSchema   int64         `json:"details_schema"`
	Modes           []string      `json:"modes"`
	Metrics         []Metric      `json:"metrics"`
	Outcomes        []Outcome     `json:"outcomes"`
	Reasons         []string      `json:"reasons"`
	Updates         []Update      `json:"updates"`
	PayloadLimits   PayloadLimits `json:"payload_limits"`
}

// Category is a plugin evaluated by the host engine.
//
// Evaluation timing: during continuous operation the engine invokes a
// category when its visible input changes (a fact becomes available, or a
// fact's source boundary at or after that availability passes), at arm
// deadlines, and at the first pass at or after a wake (a NextLogicalAt the
// category requested, or one the engine sets to retry a failed call). Catch-up
// after downtime also invokes at earlier source boundaries of facts that were
// not yet visible, unless the category opts in through VisibleInputReplay.
type Category interface {
	Describe() Descriptor
	ValidatePolicy(context.Context, Payload) error
	Evaluate(context.Context, Request) (Result, error)
	ValidateResult(context.Context, Request, Result) error
}

// VisibleInputReplay opts a category into skipping hidden source events whose
// rolling input has not changed. Deadlines, availability and eligible source
// events still run. Categories with additional time-driven behavior must opt out.
type VisibleInputReplay interface {
	Category
	// ReplaysVisibleInputOnly reports whether the conditions above hold. A
	// wrapper whose own results depend on logical time must return false.
	ReplaysVisibleInputOnly() bool
	// ReplaySampleWindows returns the category's rolling sample history
	// length and maximum endpoint age. While tracking an active occurrence
	// with no fresh sample, losing older samples cannot change its result.
	// Zero disables pruning.
	ReplaySampleWindows(context.Context, Payload) (history, freshness time.Duration)
}

// StaleSampleReplay lets a category coalesce sample-only changes while an
// active, finalized occurrence has no fresh samples, timers or qualified
// evidence. In that state admitting stale samples or losing them from history
// must leave both tracker and arm unchanged.
type StaleSampleReplay interface {
	VisibleInputReplay
	CoalescesStaleFinalSamples() bool
}

type FeatureRef struct {
	ID          string    `json:"id"`
	Value       float64   `json:"value"`
	SourceAt    time.Time `json:"source_at"`
	AvailableAt time.Time `json:"available_at"`
}
type Occurrence struct {
	PolicyID   string `json:"policy_id"`
	Occurrence int64  `json:"occurrence"`
}
type Fallback struct {
	Schema     int64     `json:"schema"`
	DueAt      time.Time `json:"due_at"`
	Action     string    `json:"action"`
	Route      string    `json:"route"`
	Summary    string    `json:"summary"`
	TerminalID string    `json:"terminal_id"`
}
type Entry struct {
	Basis       string    `json:"basis"`
	AvailableAt time.Time `json:"available_at"`
	BundleID    string    `json:"bundle_id"`
	Support     []string  `json:"support"`
	Fallback    Fallback  `json:"fallback"`
}
type Terminal struct {
	DecisionID        string       `json:"decision_id"`
	LogicalAt         time.Time    `json:"logical_at"`
	Action            string       `json:"action"`
	Endpoint          *FeatureRef  `json:"endpoint,omitempty"`
	UrgentOccurrences []Occurrence `json:"urgent_occurrences"`
}
type SharedContext struct {
	Payload     Payload   `json:"payload"`
	AvailableAt time.Time `json:"available_at"`
	BundleID    string    `json:"bundle_id"`
	Revision    int64     `json:"revision"`
}
type Bundle struct {
	ID                 string    `json:"id"`
	Run                string    `json:"run"`
	Asset              string    `json:"asset"`
	LogicalAt          time.Time `json:"logical_at"`
	AvailabilityCutoff time.Time `json:"availability_cutoff"`
	LookbackSeconds    int64     `json:"lookback_seconds"`
	Facts              []string  `json:"facts"`
	Features           []string  `json:"features"`
}
type Fact struct {
	ID          string          `json:"id"`
	Run         string          `json:"run"`
	Asset       string          `json:"asset"`
	Kind        string          `json:"kind"`
	AvailableAt time.Time       `json:"available_at"`
	Body        json.RawMessage `json:"body"`
}
type Provenance struct {
	Mode                  string `json:"mode"`
	CollectionRunID       string `json:"collection_run_id"`
	Operation             string `json:"operation"`
	ScheduleRevision      int64  `json:"schedule_revision"`
	InventoryRevision     string `json:"inventory_revision"`
	SourceRecord          string `json:"source_record"`
	JobID                 string `json:"job_id,omitempty"`
	ConfigurationRevision *int64 `json:"configuration_revision,omitempty"`
	WorkID                string `json:"work_id,omitempty"`
	CollectorID           string `json:"collector_id,omitempty"`
	UploadProfileID       string `json:"upload_profile_id,omitempty"`
	UploadProfileHash     string `json:"upload_profile_hash,omitempty"`
}
type Sample struct {
	Metric       string     `json:"metric"`
	Unit         string     `json:"unit"`
	SourceAt     time.Time  `json:"source_at"`
	CollectedAt  time.Time  `json:"collected_at"`
	CompletedAt  time.Time  `json:"completed_at"`
	Value        float64    `json:"value"`
	SourceRecord string     `json:"source_record"`
	Provenance   Provenance `json:"provenance"`
}
type Coverage struct {
	Metric       string    `json:"metric"`
	From         time.Time `json:"from"`
	Through      time.Time `json:"through"`
	Code         string    `json:"code"`
	SourceRecord string    `json:"source_record"`
}
type SnapshotEntry struct {
	Metric   string    `json:"metric"`
	SourceAt time.Time `json:"source_at"`
	Value    *float64  `json:"value,omitempty"`
	Unit     string    `json:"unit"`
	Support  string    `json:"support"`
}
type Qualified struct {
	PolicyID           string          `json:"policy_id"`
	Occurrence         int64           `json:"occurrence"`
	Transition         string          `json:"transition"`
	Rule               string          `json:"rule"`
	RuleVersion        int64           `json:"rule_version"`
	EnrollmentRevision int64           `json:"enrollment_revision"`
	Severity           string          `json:"severity"`
	QualifiedAt        time.Time       `json:"qualified_at"`
	Snapshot           []SnapshotEntry `json:"snapshot"`
}
type Conflict struct {
	Metric   string    `json:"metric"`
	SourceAt time.Time `json:"source_at"`
	Values   []string  `json:"values"`
	Code     string    `json:"code"`
}
type ProvenanceFact struct {
	SampleID     string     `json:"sample_id"`
	SourceRecord string     `json:"source_record"`
	Provenance   Provenance `json:"provenance"`
}
type TrackerContext struct {
	Category string  `json:"category"`
	Revision int64   `json:"revision"`
	Payload  Payload `json:"payload"`
	BundleID string  `json:"bundle_id"`
}
type Feature struct {
	FeatureKind string    `json:"feature_kind"`
	SourceAt    time.Time `json:"source_at"`
	Value       float64   `json:"value"`
	Unit        string    `json:"unit"`
	Support     []string  `json:"support"`
}
type Request struct {
	Contract           int64          `json:"contract"`
	Implementation     int64          `json:"implementation"`
	Category           string         `json:"category"`
	Run                string         `json:"run"`
	Asset              string         `json:"asset"`
	DescriptorHash     string         `json:"descriptor_hash"`
	ConfigHash         string         `json:"config_hash"`
	Purpose            string         `json:"purpose"`
	Scope              string         `json:"scope"`
	Sequence           int64          `json:"sequence"`
	ExpectedRevision   int64          `json:"expected_revision"`
	CandidateID        string         `json:"candidate_id,omitempty"`
	BudgetMS           *int64         `json:"budget_ms,omitempty"`
	LogicalAt          time.Time      `json:"logical_at"`
	AvailabilityCutoff time.Time      `json:"availability_cutoff"`
	ExecutedAt         time.Time      `json:"executed_at"`
	DiscoveryFloor     time.Time      `json:"discovery_floor"`
	Bundle             Bundle         `json:"bundle"`
	Facts              []Fact         `json:"facts"`
	SharedContext      *SharedContext `json:"shared_context,omitempty"`
	Policy             Payload        `json:"policy"`
	State              *Payload       `json:"state,omitempty"`
	Entry              *Entry         `json:"entry,omitempty"`
	Terminal           *Terminal      `json:"terminal,omitempty"`
}
type Result struct {
	Kind                  string     `json:"kind"`
	State                 *Payload   `json:"state,omitempty"`
	InitialCandidateState *Payload   `json:"initial_candidate_state,omitempty"`
	Phase                 string     `json:"phase,omitempty"`
	Action                string     `json:"action,omitempty"`
	Outcome               string     `json:"outcome,omitempty"`
	UpdateCodes           []string   `json:"update_codes"`
	Reasons               []string   `json:"reasons"`
	Support               []string   `json:"support"`
	Summary               string     `json:"summary"`
	Details               *Payload   `json:"details,omitempty"`
	NextLogicalAt         *time.Time `json:"next_logical_at,omitempty"`
	ProposedFeatures      []Feature  `json:"proposed_features"`
	TerminalEndpointID    string     `json:"terminal_endpoint_id,omitempty"`
	EntryQualifiedAt      *time.Time `json:"entry_qualified_at,omitempty"`
}
