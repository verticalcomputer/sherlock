package collectorruntime

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/collectorpop"
)

type captureRoundTripper struct{ request *http.Request }

func (c *captureRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	c.request = request
	return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody, Header: make(http.Header), Request: request}, nil
}

func TestAccessServiceTokenPoPTransportAddsBoundHeaders(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "collector"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	capture := &captureRoundTripper{}
	roundTripper, err := newAccessServiceTokenRoundTripper(capture, AccessServiceToken{ClientID: "client.access", ClientSecret: "secret"}, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, func() time.Time { return time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC) }, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"version":"1"}`)
	request, _ := http.NewRequest(http.MethodPost, "https://collector.example/collector/v1/heartbeat", bytes.NewReader(body))
	request.Header.Set(collectorpop.ProtocolHeader, "1")
	request.Header.Set(collectorpop.CorrelationHeader, "correlation")
	if _, err := roundTripper.RoundTrip(request); err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{"CF-Access-Client-Id", "CF-Access-Client-Secret", collectorpop.CertificateHeader, collectorpop.TimestampHeader, collectorpop.ContentHashHeader, collectorpop.SignatureHeader} {
		if capture.request.Header.Get(header) == "" {
			t.Fatalf("missing header %s", header)
		}
	}
	if request.Header.Get("CF-Access-Client-Secret") != "" {
		t.Fatal("caller request was mutated")
	}
	remaining, err := io.ReadAll(request.Body)
	if err != nil || !bytes.Equal(remaining, body) {
		t.Fatalf("caller request body was consumed: body=%q err=%v", remaining, err)
	}
}

func TestReadAccessServiceTokenRequiresOwnerOnlyFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "token.json")
	encoded, _ := json.Marshal(AccessServiceToken{ClientID: "client.access", ClientSecret: "secret"})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAccessServiceToken(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAccessServiceToken(path); err == nil {
		t.Fatal("expected permissive credential-file rejection")
	}
}
