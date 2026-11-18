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
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type coolingProcessFixture struct {
	profile domain.CoolingUploadProfile
	pool    *pgxpool.Pool
}

func exerciseSharedUploadProcess(t *testing.T, ctx context.Context, binary, dsn string, caPEM, caKey []byte,
	firstID domain.CollectorID, firstSource domain.SourceID, firstCert tls.Certificate, firstPayload []byte,
	secondID domain.CollectorID, secondSource domain.SourceID, secondCert tls.Certificate, secondPayload []byte,
	cooling ...coolingProcessFixture) {
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
	var profileHash string
	if len(cooling) == 1 {
		body, err := json.Marshal(cooling[0].profile)
		if err != nil {
			t.Fatal(err)
		}
		profilePath := filepath.Join(root, "cooling-profile.json")
		if err := os.WriteFile(profilePath, body, 0o600); err != nil {
			t.Fatal(err)
		}
		profileHash = domain.ChecksumSHA256(body).String()
		// Exercise optional assessment startup failure in the real intake process;
		// it must leave both upload routes running and must never use the intake DSN.
		fixtureConfig, err := os.ReadFile("../../../test/assessment/v1/config.json")
		if err != nil {
			t.Fatal(err)
		}
		assessmentPath := filepath.Join(root, "assessment.json")
		if err := os.WriteFile(assessmentPath, fixtureConfig, 0o600); err != nil {
			t.Fatal(err)
		}
		process.Env = append(process.Env, "SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILE="+profilePath,
			"SHERLOCK_ASSESSMENT_MODE=shadow", "SHERLOCK_ASSESSMENT_CONFIG_FILE="+assessmentPath,
			"SHERLOCK_ASSESSMENT_DATABASE_URL=postgres://unused@127.0.0.1:1/unavailable?sslmode=disable&connect_timeout=1")
	}
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
	if len(cooling) == 1 {
		f := cooling[0]
		slot := time.Now().UTC().Truncate(domain.CoolingUploadInterval).Add(domain.CoolingUploadInterval)
		timer := time.NewTimer(time.Until(slot))
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
		asset := f.profile.Assets[0]
		task := f.profile.Task(domain.QueryGPUTemperature, slot)
		completed := time.Now().UTC()
		sourceAt := slot.Add(-time.Second)
		entity := domain.EntityIdentity{ClusterID: f.profile.ClusterID, Kind: domain.EntityGPU,
			NodeID: asset.NodeID, PhysicalGPUUUID: asset.GPUUUID}
		report := domain.CoolingUploadReport{Version: 2, ProfileID: f.profile.ProfileID,
			ProfileRevision: f.profile.Revision, ProfileHash: profileHash,
			Result: domain.CollectionResult{Task: task, Status: domain.ResultSucceeded, StartedAt: slot, CompletedAt: completed,
				Coverage: domain.Coverage{Complete: true, SeriesReturned: 1, BytesRead: 100},
				Observations: []domain.Observation{{ID: "cooling-process-observation", SchemaVersion: 1,
					ClusterID: f.profile.ClusterID, SourceID: f.profile.SourceID, Kind: "gpu_temperature",
					EntityKey: entity.Key(), Metric: "DCGM_FI_DEV_GPU_TEMP", Unit: "celsius", Value: 60,
					Labels:     domain.SortedLabels(map[string]string{"Hostname": string(asset.NodeID), "UUID": string(asset.GPUUUID)}),
					ObservedAt: sourceAt, CollectedAt: completed, SourceReference: domain.DCGMSourceReference(task.Query)}}}}
		payload, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		for _, upload := range []struct {
			client *http.Client
			want   int
		}{{first, http.StatusNoContent}, {first, http.StatusNoContent}, {second, http.StatusForbidden}} {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+address+domain.CoolingUploadPath, bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Sherlock-Protocol-Version", "2")
			req.Header.Set("X-Correlation-ID", "cooling-process")
			response, err := upload.client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
			response.Body.Close()
			if response.StatusCode != upload.want {
				t.Fatalf("V2 status=%d want=%d body=%s", response.StatusCode, upload.want, body)
			}
		}
		var receipts int
		var observed time.Time
		if err := f.pool.QueryRow(ctx, `SELECT count(*),min(o.observed_at) FROM prometheus_cooling_upload_receipts r
 JOIN observations o USING(run_id) WHERE r.run_id=$1`, task.RunID).Scan(&receipts, &observed); err != nil || receipts != 1 || !observed.Equal(sourceAt) {
			t.Fatalf("V2 receipt/sample=%d observed=%s err=%v", receipts, observed, err)
		}
		status, err := send(first, firstPayload)
		if err != nil || status != http.StatusNoContent {
			t.Fatalf("V1 stopped after V2: status=%d err=%v", status, err)
		}
		logBody, _ := os.ReadFile(filepath.Join(root, "intake.log"))
		if !bytes.Contains(logBody, []byte("control.assessment_disabled")) || !bytes.Contains(logBody, []byte("dedicated database unavailable")) {
			t.Fatalf("optional assessment startup not observed: %s", logBody)
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
