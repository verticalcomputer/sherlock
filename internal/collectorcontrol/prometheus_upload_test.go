package collectorcontrol

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type sharedUploadStore struct {
	allowed bool
	err     error
	writes  int
}

func (s *sharedUploadStore) PrometheusUploadSourceAllowed(context.Context, domain.ClusterID, domain.SourceID) (bool, error) {
	return s.allowed, s.err
}

func (s *sharedUploadStore) RecordPrometheusReport(context.Context, domain.PrometheusReport) (bool, error) {
	s.writes++
	return true, nil
}

func TestSharedUploadFailsClosedBeforeAcceptingPayload(t *testing.T) {
	cert := &x509.Certificate{SerialNumber: big.NewInt(7), Raw: []byte("test certificate")}
	auth := &fakeAuthenticator{certificate: cert}
	store := &sharedUploadStore{allowed: true}
	bindings := []PrometheusUploadBinding{{CollectorID: "collector-1", SourceID: "source-1"}}
	handler, err := NewSharedPrometheusUploadHandler(auth, DirectMTLSAuthenticator{}, store, transportClock{}, bindings)
	if err != nil {
		t.Fatal(err)
	}
	// Mutating the caller's configuration cannot alter a running handler.
	bindings[0].CollectorID = "different-collector"
	for _, test := range []struct {
		name    string
		allowed bool
		err     error
		status  int
	}{
		{"bound readiness", true, nil, http.StatusBadRequest},
		{"wrong source ownership", false, nil, http.StatusForbidden},
		{"source lookup unavailable", false, errors.New("database unavailable"), http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			store.allowed, store.err = test.allowed, test.err
			request := httptest.NewRequest(http.MethodPost, domain.PrometheusUploadPath, nil)
			request.Header.Set(protocolHeader, "1")
			request.Header.Set(correlationHeader, "scope-test")
			request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || store.writes != 0 {
				t.Fatalf("status=%d writes=%d", response.Code, store.writes)
			}
		})
	}
}

func TestSharedUploadRejectsInvalidBindingConstruction(t *testing.T) {
	for _, bindings := range [][]PrometheusUploadBinding{
		nil,
		{{CollectorID: "one"}},
		{{CollectorID: "one", SourceID: "source"}, {CollectorID: "one", SourceID: "other"}},
	} {
		if _, err := NewSharedPrometheusUploadHandler(&fakeAuthenticator{}, DirectMTLSAuthenticator{}, &sharedUploadStore{}, transportClock{}, bindings); err == nil {
			t.Fatal("invalid bindings were accepted")
		}
	}
}
