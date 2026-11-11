//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func exerciseSharedUploadProcess(t *testing.T, ctx context.Context, binary, dsn string, caPEM, caKey []byte,
	firstID domain.CollectorID, firstSource domain.SourceID, firstCert tls.Certificate, firstPayload []byte,
	secondID domain.CollectorID, secondSource domain.SourceID, secondCert tls.Certificate, secondPayload []byte) {
	t.Helper()
	root := t.TempDir()
	block, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(caKey)
	issuer, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	server := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, server, ca, serverKey.Public(), issuer)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"server.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"server.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), "ca.crt": caPEM,
	} {
		if err := os.WriteFile(filepath.Join(root, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	bindings, err := json.Marshal([]map[string]string{
		{"collector_id": string(firstID), "source_id": string(firstSource)},
		{"collector_id": string(secondID), "source_id": string(secondSource)},
	})
	if err != nil {
		t.Fatal(err)
	}
	process := exec.CommandContext(ctx, binary, "prometheus-upload")
	process.Dir = root
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "SHERLOCK_") {
			process.Env = append(process.Env, value)
		}
	}
	process.Env = append(process.Env, "SHERLOCK_DATABASE_URL="+dsn, "SHERLOCK_CONTROL_ADDRESS="+address,
		"SHERLOCK_CONTROL_CERT_FILE="+filepath.Join(root, "server.crt"), "SHERLOCK_CONTROL_KEY_FILE="+filepath.Join(root, "server.key"),
		"SHERLOCK_COLLECTOR_CA_FILE="+filepath.Join(root, "ca.crt"), "SHERLOCK_PROMETHEUS_UPLOAD_BINDINGS="+string(bindings))
	log, err := os.Create(filepath.Join(root, "intake.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	process.Stdout, process.Stderr = log, log
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = process.Process.Kill() }()
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	client := func(cert tls.Certificate) *http.Client {
		transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{cert}}}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 2 * time.Second}
	}
	first, second := client(firstCert), client(secondCert)
	send := func(c *http.Client, payload []byte) (int, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+address+domain.PrometheusUploadPath, bytes.NewReader(payload))
		if err != nil {
			return 0, err
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Sherlock-Protocol-Version", "1")
		request.Header.Set("X-Correlation-ID", fmt.Sprintf("binary-%d", time.Now().UnixNano()))
		response, err := c.Do(request)
		if err != nil {
			return 0, err
		}
		response.Body.Close()
		return response.StatusCode, nil
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		status, err := send(first, []byte("{}"))
		if err == nil && status == http.StatusBadRequest {
			break
		}
		if time.Now().After(deadline) {
			raw, _ := os.ReadFile(filepath.Join(root, "intake.log"))
			t.Fatalf("shared binary readiness status=%d err=%v log=%s", status, err, raw)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, upload := range []struct {
		client  *http.Client
		payload []byte
		status  int
	}{{first, firstPayload, 204}, {second, secondPayload, 204}, {first, secondPayload, 400}, {second, firstPayload, 400}} {
		status, err := send(upload.client, upload.payload)
		if err != nil || status != upload.status {
			t.Fatalf("shared binary upload status=%d want=%d err=%v", status, upload.status, err)
		}
	}
	if err := process.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shared binary shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shared binary did not shut down gracefully")
	}
	t.Log("built shared intake accepted both authenticated collectors, rejected swapped payloads and shut down gracefully")
}
