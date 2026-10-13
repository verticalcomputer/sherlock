// Package clustermemory defines Sherlock's rebuildable, cluster-scoped memory
// projection. Retrieved entries are untrusted hints and never evidence.
package clustermemory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	SchemaVersion = 1
	IndexVersion  = "lexical-v1"
)

type Mode string

const (
	ModeDisabled Mode = "DISABLED"
	ModeShadow   Mode = "SHADOW"
	ModeEnabled  Mode = "ENABLED"
)

func (mode Mode) Validate() error {
	switch mode {
	case ModeDisabled, ModeShadow, ModeEnabled:
		return nil
	default:
		return fmt.Errorf("unknown cluster memory mode %q", mode)
	}
}

type Kind string
type TrustClass string

const (
	KindValidatedFinding Kind = "VALIDATED_FINDING"
	KindActionOutcome    Kind = "ACTION_OUTCOME"
	KindCoverageGap      Kind = "COVERAGE_GAP"
	KindHypothesis       Kind = "HYPOTHESIS"
	KindOperatorReview   Kind = "OPERATOR_REVIEW"

	TrustObserved         TrustClass = "OBSERVED"
	TrustValidatedFinding TrustClass = "VALIDATED_FINDING"
	TrustHypothesis       TrustClass = "HYPOTHESIS"
	TrustActionOutcome    TrustClass = "ACTION_OUTCOME"
	TrustCoverageGap      TrustClass = "COVERAGE_GAP"
	TrustOperatorReview   TrustClass = "OPERATOR_REVIEW"
)

type Citation struct {
	EvidenceID   domain.EvidenceID
	Relationship string
}

type Entry struct {
	ID                    string
	ClusterID             domain.ClusterID
	Kind                  Kind
	Trust                 TrustClass
	SourceInvestigationID domain.InvestigationID
	SourceActionID        string
	SourceFindingID       domain.FindingID
	EntityKind            string
	EntityIDs             []string
	EvidenceClass         string
	SourceVersion         string
	Statement             string
	Summary               string
	ObservedFrom          time.Time
	ObservedTo            time.Time
	ValidFrom             time.Time
	ValidTo               time.Time
	CreatedAt             time.Time
	ExpiresAt             time.Time
	SupersededAt          time.Time
	Completeness          string
	Freshness             string
	RetentionClass        string
	ContentDigest         domain.SHA256
	IdempotencyKey        string
	Citations             []Citation
	Rank                  float64
}

func (entry Entry) Validate() error {
	if entry.ID == "" || entry.ClusterID == "" || entry.SourceInvestigationID == "" ||
		strings.TrimSpace(entry.EntityKind) == "" || len(entry.EntityIDs) == 0 ||
		strings.TrimSpace(entry.Statement) == "" || strings.TrimSpace(entry.Summary) == "" ||
		entry.ValidFrom.IsZero() || entry.CreatedAt.IsZero() || entry.RetentionClass == "" ||
		entry.ContentDigest == (domain.SHA256{}) || entry.IdempotencyKey == "" {
		return errors.New("cluster memory attribution is incomplete")
	}
	if entry.Kind == KindValidatedFinding && entry.SourceFindingID == "" {
		return errors.New("validated finding memory requires a source finding")
	}
	if entry.Kind != KindCoverageGap && entry.Kind != KindHypothesis && len(entry.Citations) == 0 {
		return errors.New("factual cluster memory requires a durable citation")
	}
	if entry.ValidTo.Before(entry.ValidFrom) && !entry.ValidTo.IsZero() || entry.ObservedTo.Before(entry.ObservedFrom) && !entry.ObservedTo.IsZero() {
		return errors.New("cluster memory time range is invalid")
	}
	if !slices.Contains([]string{"COMPLETE", "PARTIAL", "UNKNOWN"}, entry.Completeness) || !slices.Contains([]string{"CURRENT", "STALE", "UNKNOWN"}, entry.Freshness) {
		return errors.New("cluster memory quality classification is invalid")
	}
	return nil
}

type Query struct {
	ClusterID      domain.ClusterID
	Text           string
	EntityIDs      []string
	ValidAt        time.Time
	MaximumAge     time.Duration
	Limit          int
	TokenAllowance int64
}

type Result struct {
	Candidates   int
	Entries      []Entry
	Latency      time.Duration
	IndexVersion string
	Fallback     string
}

type Reader interface {
	Retrieve(context.Context, Query) (Result, error)
}

// Embedder is deliberately provider-neutral. Implementations receive only the
// already-redacted compact statement and never authoritative evidence bodies.
type Embedder interface {
	Embed(context.Context, string, []string) ([][]float32, error)
	ModelVersion() (model, version string)
}

type Projector interface {
	ProjectInvestigation(context.Context, domain.InvestigationID) error
	RebuildCluster(context.Context, domain.ClusterID) error
}
