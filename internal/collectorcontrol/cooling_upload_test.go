package collectorcontrol

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type coolingUploadStoreStub struct {
	accepted bool
	err      error
	writes   int
}

func (s *coolingUploadStoreStub) RecordCoolingUpload(_ context.Context, collector domain.CollectorID, cluster domain.ClusterID, _ domain.CoolingUploadReport) (bool, error) {
	s.writes++
	if collector != "collector-1" || cluster != "cluster-1" {
		return false, errors.New("wrong authenticated caller passed to storage")
	}
	return s.accepted, s.err
}

func TestCoolingUploadHandler(t *testing.T) { testCoolingUploadHandler(t, domain.CoolingUploadVersion) }
func TestContinuousCoolingUploadHandler(t *testing.T) {
	testCoolingUploadHandler(t, domain.CoolingUploadProductionVersion)
}
func testCoolingUploadHandler(t *testing.T, version int) {
	certificate := &x509.Certificate{SerialNumber: big.NewInt(7), Raw: []byte("cooling test certificate")}
	profile := domain.CoolingUploadProfile{Version: 2, ProfileID: "cooling", Revision: 1, CollectorID: "collector-1",
		ClusterID: "cluster-1", SourceID: "source-1", InventoryRevision: "inventory", StartsAt: transportNow.Add(-time.Minute),
		EndsAt: transportNow.Add(time.Hour), Assets: []domain.CoolingUploadAsset{{NodeID: "node", GPUUUID: "GPU-1"}}}
	if version == domain.CoolingUploadProductionVersion {
		profile.Version = version
		profile.EndsAt = time.Time{}
		profile.State = "ENABLED"
	}
	hash := domain.ChecksumSHA256([]byte("approval")).String()
	report := domain.CoolingUploadReport{Version: version, ProfileID: profile.ProfileID, ProfileRevision: profile.Revision, ProfileHash: hash,
		Result: domain.CollectionResult{Task: profile.Task(domain.QueryGPUTemperature, transportNow), Status: domain.ResultFailed,
			StartedAt: transportNow, CompletedAt: transportNow,
			Failures: []domain.CollectionFailure{{Code: domain.FailureSourceUnavailable, Message: "source unavailable"}}}}
	encode := func(r domain.CoolingUploadReport) []byte {
		body, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	canonical := encode(report)
	badHash := report
	badHash.ProfileHash = domain.ChecksumSHA256([]byte("different")).String()
	badSource := report
	badSource.Result.Task.SourceID = "source-2"
	for _, tc := range []struct {
		name         string
		path         string
		protocol     string
		body         []byte
		unauth       bool
		identityErr  error
		otherCluster bool
		storeErr     error
		accept       bool
		status       int
		writes       int
	}{
		{name: "accepted", accept: true, status: http.StatusNoContent, writes: 1},
		{name: "replay conflict", status: http.StatusConflict, writes: 1},
		{name: "durable authorization failure", storeErr: ErrCoolingUploadRejected, status: http.StatusForbidden, writes: 1},
		{name: "unavailable store", storeErr: errors.New("transaction failed"), status: http.StatusServiceUnavailable, writes: 1},
		{name: "other cluster", otherCluster: true, status: http.StatusForbidden},
		{name: "unregistered certificate", identityErr: ErrCollectorInactive, status: http.StatusUnauthorized},
		{name: "no certificate", unauth: true, status: http.StatusUnauthorized},
		{name: "wrong protocol", protocol: "1", status: http.StatusUpgradeRequired},
		{name: "no work endpoint", path: "/collector/v2/work/claim", status: http.StatusNotFound},
		{name: "distinct V1 endpoint", path: domain.PrometheusUploadPath, status: http.StatusNotFound},
		{name: "changed signed bytes", body: append([]byte{' '}, canonical...), status: http.StatusBadRequest},
		{name: "wrong hash", body: encode(badHash), status: http.StatusBadRequest},
		{name: "wrong source", body: encode(badSource), status: http.StatusBadRequest},
		{name: "oversize", body: make([]byte, domain.CoolingUploadMaxBytes+1), status: http.StatusRequestEntityTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bound := profile
			if tc.otherCluster {
				bound.ClusterID = "cluster-2"
			}
			identity := &fakeAuthenticator{certificate: certificate, err: tc.identityErr}
			store := &coolingUploadStoreStub{accepted: tc.accept, err: tc.storeErr}
			handler, err := NewCoolingUploadHandler(identity, DirectMTLSAuthenticator{}, store, transportClock{}, bound, hash)
			if err != nil {
				t.Fatal(err)
			}
			path, protocol, body := tc.path, tc.protocol, tc.body
			if path == "" {
				path = domain.CoolingUploadPath
			}
			if protocol == "" {
				protocol = "2"
			}
			if body == nil {
				body = canonical
			}
			request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
			request.Header.Set(protocolHeader, protocol)
			request.Header.Set(correlationHeader, "cooling-report")
			request.Header.Set("Content-Type", "application/json")
			if !tc.unauth {
				request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.status || store.writes != tc.writes {
				t.Fatalf("response=%d writes=%d body=%s", response.Code, store.writes, response.Body.String())
			}
		})
	}
}
