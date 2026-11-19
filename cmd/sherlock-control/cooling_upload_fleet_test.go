package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type intakeFleetIdentity struct{ second bool }

func (i intakeFleetIdentity) AuthenticateCollectorIdentity(context.Context, string, [32]byte) (collectorcontrol.AuthenticatedIdentity, error) {
	if i.second {
		return collectorcontrol.AuthenticatedIdentity{CollectorID: "collector-2", ClusterID: "cluster-2"}, nil
	}
	return collectorcontrol.AuthenticatedIdentity{CollectorID: "collector-1", ClusterID: "cluster-1"}, nil
}

type intakeFleetClock struct{ at time.Time }

func (c intakeFleetClock) Now() time.Time { return c.at }

type intakeFleetStore struct {
	registrations, writes int
	timeoutFirst          bool
}

func (s *intakeFleetStore) RegisterCoolingUploadProfile(ctx context.Context, p domain.CoolingUploadProfile, _ string) error {
	s.registrations++
	if s.timeoutFirst {
		if p.CollectorID == "collector-1" {
			<-ctx.Done()
			return ctx.Err()
		}
		return ctx.Err()
	}
	if p.CollectorID == "collector-2" {
		return errors.New("cluster two admission unavailable")
	}
	return nil
}
func (s *intakeFleetStore) RecordCoolingUpload(_ context.Context, c domain.CollectorID, k domain.ClusterID, r domain.CoolingUploadReport) (bool, error) {
	s.writes++
	n := "1"
	if s.timeoutFirst {
		n = "2"
	}
	if c != domain.CollectorID("collector-"+n) || k != domain.ClusterID("cluster-"+n) || r.Result.Task.SourceID != domain.SourceID("source-"+n) {
		return false, errors.New("wrong scope")
	}
	return true, nil
}
func TestSharedCoolingAdmissionIsolationAndScopePreflight(t *testing.T) {
	for _, timeoutFirst := range []bool{false, true} {
		name := "immediate_second_failure"
		if timeoutFirst {
			name = "timed_out_first_failure"
		}
		t.Run(name, func(t *testing.T) { testSharedCoolingAdmissionIsolation(t, timeoutFirst) })
	}
}
func testSharedCoolingAdmissionIsolation(t *testing.T, timeoutFirst bool) {
	t.Setenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILE", "")
	at := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	var profiles []domain.CoolingUploadProfile
	var paths, hashes []string
	for _, n := range []string{"1", "2"} {
		p := domain.CoolingUploadProfile{Version: 3, ProfileID: "profile-" + n, Revision: 1, CollectorID: domain.CollectorID("collector-" + n), ClusterID: domain.ClusterID("cluster-" + n), SourceID: domain.SourceID("source-" + n), InventoryRevision: "inventory-" + n, StartsAt: at.Add(-time.Hour), State: "ENABLED", Assets: []domain.CoolingUploadAsset{{NodeID: "node", GPUUUID: "GPU-1"}}}
		profiles = append(profiles, p)
		body, _ := json.Marshal(p)
		path := filepath.Join(t.TempDir(), "profile.json")
		if e := os.WriteFile(path, body, 0600); e != nil {
			t.Fatal(e)
		}
		paths = append(paths, path)
		hashes = append(hashes, domain.ChecksumSHA256(body).String())
	}
	raw, _ := json.Marshal(paths)
	t.Setenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILES", string(raw))
	store := &intakeFleetStore{timeoutFirst: timeoutFirst}
	base := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	scope := config.PrometheusUploadScope{Bindings: []config.PrometheusUploadBinding{{CollectorID: "collector-1", SourceID: "source-1"}}}
	configureCoolingUpload(t.Context(), base, intakeFleetIdentity{}, collectorcontrol.DirectMTLSAuthenticator{}, store, intakeFleetClock{at}, scope, logger)
	if store.registrations != 0 {
		t.Fatal("partially registered set outside allow-list")
	}
	scope.Bindings = append(scope.Bindings, config.PrometheusUploadBinding{CollectorID: "collector-2", SourceID: "source-2"})
	h := configureCoolingUpload(t.Context(), base, intakeFleetIdentity{second: timeoutFirst}, collectorcontrol.DirectMTLSAuthenticator{}, store, intakeFleetClock{at}, scope, logger)
	if store.registrations != 2 {
		t.Fatal("expected independent registration attempts")
	}
	selected := 0
	if timeoutFirst {
		selected = 1
	}
	r := domain.CoolingUploadReport{Version: 3, ProfileID: profiles[selected].ProfileID, ProfileRevision: 1, ProfileHash: hashes[selected], Result: domain.CollectionResult{Task: profiles[selected].Task(domain.QueryGPUPower, at), Status: domain.ResultFailed, StartedAt: at, CompletedAt: at, Failures: []domain.CollectionFailure{{Code: domain.FailureSourceUnavailable, Message: "unavailable"}}}}
	body, _ := json.Marshal(r)
	req := httptest.NewRequest("POST", domain.CoolingUploadPath, strings.NewReader(string(body)))
	req.Header.Set("X-Sherlock-Protocol-Version", "2")
	req.Header.Set("X-Correlation-ID", "fleet")
	req.Header.Set("Content-Type", "application/json")
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Raw: []byte("fixture")}
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 204 || store.writes != 1 {
		t.Fatalf("one rejected profile disabled the other: status%d writes%d %s", rec.Code, store.writes, rec.Body.String())
	}
}
