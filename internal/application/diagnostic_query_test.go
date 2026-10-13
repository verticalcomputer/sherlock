package application

import (
	"context"
	"errors"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestDiagnosticQueriesEnforcesClusterScope(t *testing.T) {
	reader := &diagnosticProjectionReaderFake{projection: DiagnosticRunProjection{RunID: "run-1", ClusterID: "other-cluster"}, found: true}
	queries, err := NewDiagnosticQueries(reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := queries.GetRun(context.Background(), "cluster-1", "run-1"); err == nil {
		t.Fatal("expected mismatched cluster projection rejection")
	}
	if reader.clusterID != "cluster-1" || reader.runID != "run-1" {
		t.Fatalf("reader scope = %s/%s", reader.clusterID, reader.runID)
	}
}

func TestDiagnosticQueriesPreservesNotFoundAndStoreError(t *testing.T) {
	reader := &diagnosticProjectionReaderFake{}
	queries, _ := NewDiagnosticQueries(reader)
	if _, found, err := queries.GetRun(context.Background(), "cluster-1", "run-1"); err != nil || found {
		t.Fatalf("not found: found=%t err=%v", found, err)
	}
	reader.err = errors.New("database unavailable")
	if _, _, err := queries.GetRun(context.Background(), "cluster-1", "run-1"); err == nil {
		t.Fatal("expected store error")
	}
	if _, _, err := queries.GetRun(context.Background(), "", "run-1"); err == nil {
		t.Fatal("expected empty cluster rejection")
	}
}

type diagnosticProjectionReaderFake struct {
	projection DiagnosticRunProjection
	found      bool
	err        error
	clusterID  domain.ClusterID
	runID      domain.DiagnosticRunID
}

func (fake *diagnosticProjectionReaderFake) GetDiagnosticRunProjection(_ context.Context, clusterID domain.ClusterID, runID domain.DiagnosticRunID) (DiagnosticRunProjection, bool, error) {
	fake.clusterID, fake.runID = clusterID, runID
	return fake.projection, fake.found, fake.err
}
