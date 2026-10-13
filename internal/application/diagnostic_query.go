package application

import (
	"context"
	"fmt"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// DiagnosticRunProjection is the safe read model for the diagnostic-run API.
// It intentionally omits argument values, lease tokens, raw output and all
// credential material.
type DiagnosticRunProjection struct {
	RunID       domain.DiagnosticRunID
	ClusterID   domain.ClusterID
	Definition  domain.DiagnosticDefinitionRef
	Privilege   domain.DiagnosticPrivilege
	Status      domain.DiagnosticRunStatus
	RequestedBy string
	RequestedAt time.Time
	Deadline    time.Time
	CompletedAt *time.Time
	Version     int
	WorkID      domain.DiagnosticWorkID
	Attempts    []DiagnosticAttemptProjection
}

type DiagnosticAttemptProjection struct {
	Attempt      int
	RunnerID     string
	Status       domain.DiagnosticAttemptStatus
	LeaseExpires time.Time
	PlanDigest   *domain.SHA256
	StartedAt    *time.Time
	CompletedAt  *time.Time
	Targets      []domain.DiagnosticTargetResult
}

type DiagnosticProjectionReader interface {
	GetDiagnosticRunProjection(context.Context, domain.ClusterID, domain.DiagnosticRunID) (DiagnosticRunProjection, bool, error)
}

// DiagnosticQueries owns tenant scoping for diagnostic read use cases. The
// store applies the same cluster predicate as defense in depth.
type DiagnosticQueries struct {
	reader DiagnosticProjectionReader
}

func NewDiagnosticQueries(reader DiagnosticProjectionReader) (*DiagnosticQueries, error) {
	if reader == nil {
		return nil, fmt.Errorf("diagnostic projection reader is required")
	}
	return &DiagnosticQueries{reader: reader}, nil
}

func (queries *DiagnosticQueries) GetRun(ctx context.Context, clusterID domain.ClusterID, runID domain.DiagnosticRunID) (DiagnosticRunProjection, bool, error) {
	if clusterID == "" || runID == "" {
		return DiagnosticRunProjection{}, false, fmt.Errorf("cluster and diagnostic run identifiers are required")
	}
	projection, found, err := queries.reader.GetDiagnosticRunProjection(ctx, clusterID, runID)
	if err != nil {
		return DiagnosticRunProjection{}, false, fmt.Errorf("get diagnostic run %s: %w", runID, err)
	}
	if !found {
		return DiagnosticRunProjection{}, false, nil
	}
	if projection.ClusterID != clusterID || projection.RunID != runID {
		return DiagnosticRunProjection{}, false, fmt.Errorf("diagnostic projection scope mismatch")
	}
	return projection, true, nil
}
