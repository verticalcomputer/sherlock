package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestCoolingUploadCannotWidenIntakeBindings(t *testing.T) {
	p := domain.CoolingUploadProfile{CollectorID: "collector", ClusterID: "cluster", SourceID: "source"}
	for _, tc := range []struct {
		scope config.PrometheusUploadScope
		want  bool
	}{
		{config.PrometheusUploadScope{CollectorID: "collector", ClusterID: "cluster", SourceID: "source"}, true},
		{config.PrometheusUploadScope{CollectorID: "collector", ClusterID: "other", SourceID: "source"}, false},
		{config.PrometheusUploadScope{CollectorID: "collector", ClusterID: "cluster", SourceID: "other"}, false},
		{config.PrometheusUploadScope{Bindings: []config.PrometheusUploadBinding{{CollectorID: "collector", SourceID: "source"}}}, true},
		{config.PrometheusUploadScope{Bindings: []config.PrometheusUploadBinding{{CollectorID: "other", SourceID: "source"}}}, false},
		{config.PrometheusUploadScope{Bindings: []config.PrometheusUploadBinding{{CollectorID: "collector", SourceID: "other"}}}, false},
	} {
		if got := coolingUploadScopeAllowed(p, tc.scope); got != tc.want {
			t.Fatalf("scope %+v: allowed=%v, want %v", tc.scope, got, tc.want)
		}
	}
}

type rejectingCoolingStore struct{ registrations int }

func (s *rejectingCoolingStore) RegisterCoolingUploadProfile(context.Context, domain.CoolingUploadProfile, string) error {
	s.registrations++
	return errors.New("fixture admission rejected")
}

func (*rejectingCoolingStore) RecordCoolingUpload(context.Context, domain.CollectorID, domain.ClusterID, domain.CoolingUploadReport) (bool, error) {
	return false, errors.New("must not be called")
}

func TestOptionalCoolingAdmissionFailurePreservesIntake(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	profile := domain.CoolingUploadProfile{Version: 2, ProfileID: "profile", Revision: 1,
		CollectorID: "collector", ClusterID: "cluster", SourceID: "source", InventoryRevision: "inventory",
		StartsAt: start, EndsAt: start.Add(time.Hour), Assets: []domain.CoolingUploadAsset{{NodeID: "node", GPUUUID: "GPU-fixture"}}}
	body, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILE", path)
	store := new(rejectingCoolingStore)
	base := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	scope := config.PrometheusUploadScope{CollectorID: "collector", ClusterID: "cluster", SourceID: "source"}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := configureCoolingUpload(t.Context(), base, nil, nil, store, nil, scope, logger)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, domain.PrometheusUploadPath, nil))
	if response.Code != http.StatusNoContent || store.registrations != 1 {
		t.Fatalf("V1 status=%d registrations=%d", response.Code, store.registrations)
	}
	if err := os.WriteFile(path, []byte(`{"broken":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	handler = configureCoolingUpload(t.Context(), base, nil, nil, store, nil, scope, logger)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, domain.PrometheusUploadPath, nil))
	if response.Code != http.StatusNoContent || store.registrations != 1 {
		t.Fatalf("invalid optional profile affected V1: status=%d registrations=%d", response.Code, store.registrations)
	}
}
