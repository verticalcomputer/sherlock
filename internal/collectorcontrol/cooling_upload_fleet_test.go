package collectorcontrol

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fleetCoolingAuth struct {
	base   *fakeAuthenticator
	caller AuthenticatedIdentity
}

func (a fleetCoolingAuth) AuthenticateCollectorIdentity(ctx context.Context, s string, h [32]byte) (AuthenticatedIdentity, error) {
	_, e := a.base.AuthenticateCollectorIdentity(ctx, s, h)
	return a.caller, e
}

type fleetCoolingStore struct {
	writes    int
	collector domain.CollectorID
	cluster   domain.ClusterID
	report    domain.CoolingUploadReport
}

func (s *fleetCoolingStore) RecordCoolingUpload(_ context.Context, c domain.CollectorID, k domain.ClusterID, r domain.CoolingUploadReport) (bool, error) {
	s.writes++
	s.collector = c
	s.cluster = k
	s.report = r
	return true, nil
}
func TestSharedCoolingUsesAuthenticatedIdentityBeforeProfile(t *testing.T) {
	cert := &x509.Certificate{SerialNumber: big.NewInt(7), Raw: []byte("fleet certificate")}
	profiles := []CoolingUploadEnrollment{}
	for _, n := range []string{"1", "2"} {
		p := domain.CoolingUploadProfile{Version: 3, ProfileID: "profile-" + n, Revision: 2, CollectorID: domain.CollectorID("collector-" + n), ClusterID: domain.ClusterID("cluster-" + n), SourceID: domain.SourceID("source-" + n), InventoryRevision: "inventory-" + n, StartsAt: transportNow.Add(-time.Minute), State: "ENABLED", Assets: []domain.CoolingUploadAsset{{NodeID: "node-" + domain.StableNodeID(n), GPUUUID: "GPU-" + domain.PhysicalGPUUUID(n)}}}
		profiles = append(profiles, CoolingUploadEnrollment{p, domain.ChecksumSHA256([]byte(n)).String()})
	}
	for _, tc := range []struct {
		name                  string
		caller, cluster       int
		body                  int
		unauth, foreignSource bool
		want                  int
	}{{"first", 1, 1, 0, false, false, 204}, {"second", 2, 2, 1, false, false, 204}, {"first cannot submit second", 1, 1, 1, false, false, 400}, {"second cannot submit first", 2, 2, 0, false, false, 400}, {"wrong authenticated cluster", 2, 1, 1, false, false, 403}, {"foreign source", 1, 1, 0, false, true, 400}, {"unauthenticated", 1, 1, 0, true, false, 401}} {
		t.Run(tc.name, func(t *testing.T) {
			store := new(fleetCoolingStore)
			caller := AuthenticatedIdentity{CollectorID: profiles[tc.caller-1].Profile.CollectorID, ClusterID: profiles[tc.cluster-1].Profile.ClusterID}
			auth := fleetCoolingAuth{&fakeAuthenticator{certificate: cert}, caller}
			h, e := NewSharedCoolingUploadHandler(auth, DirectMTLSAuthenticator{}, store, transportClock{}, profiles)
			if e != nil {
				t.Fatal(e)
			}
			p := profiles[tc.body]
			report := domain.CoolingUploadReport{Version: 3, ProfileID: p.Profile.ProfileID, ProfileRevision: p.Profile.Revision, ProfileHash: p.Hash, Result: domain.CollectionResult{Task: p.Profile.Task(domain.QueryGPUPower, transportNow), Status: domain.ResultFailed, StartedAt: transportNow, CompletedAt: transportNow, Failures: []domain.CollectionFailure{{Code: domain.FailureSourceUnavailable, Message: "unavailable"}}}}
			if tc.foreignSource {
				report.Result.Task.SourceID = "source-forged"
			}
			body, _ := json.Marshal(report)
			req := httptest.NewRequest("POST", domain.CoolingUploadPath, bytes.NewReader(body))
			req.Header.Set(protocolHeader, "2")
			req.Header.Set(correlationHeader, "fleet-test")
			req.Header.Set("Content-Type", "application/json")
			if !tc.unauth {
				req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("got%d want%d: %s", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want == http.StatusNoContent {
				if store.writes != 1 || store.collector != caller.CollectorID || store.cluster != caller.ClusterID || store.report.Result.Task.SourceID != p.Profile.SourceID {
					t.Fatal("caller/storage authority mismatch")
				}
			} else if store.writes != 0 {
				t.Fatal("untrusted scope reached persistence")
			}
		})
	}
	for _, es := range [][]CoolingUploadEnrollment{nil, {profiles[0], profiles[0]}, {profiles[0], profiles[1], profiles[1]}} {
		if _, e := NewSharedCoolingUploadHandler(&fakeAuthenticator{certificate: cert}, DirectMTLSAuthenticator{}, new(fleetCoolingStore), transportClock{}, es); e == nil {
			t.Fatal("invalid enrollment set accepted")
		}
	}
}
