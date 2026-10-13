//go:build integration

package integration_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	adapter "github.com/verticalcomputer/sherlock/internal/adapters/prometheus"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/artifacts"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	prometheusexecution "github.com/verticalcomputer/sherlock/internal/collectorexecution/prometheus"
	"github.com/verticalcomputer/sherlock/internal/collectorruntime"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

type directCollectorControlClient struct {
	collectorID domain.CollectorID
	store       *storepg.CollectorControlStore
}

func (c directCollectorControlClient) Heartbeat(context.Context, collectorruntime.Heartbeat) error {
	return nil
}

func (c directCollectorControlClient) Claim(ctx context.Context, request collectorruntime.ClaimRequest) (*domain.WorkLease, error) {
	lease, found, err := c.store.ClaimWork(ctx, request.CollectorID, "integration-lease-token", 2*time.Second)
	if err != nil || !found {
		return nil, err
	}
	return &lease, nil
}

func (c directCollectorControlClient) Start(ctx context.Context, reference collectorruntime.LeaseRef) error {
	return c.store.AcknowledgeWorkStart(ctx, c.collectorID, reference.WorkID, reference.Attempt, reference.LeaseToken)
}

func (c directCollectorControlClient) Renew(ctx context.Context, reference collectorruntime.LeaseRef) (time.Time, error) {
	err := c.store.RenewWorkLease(ctx, c.collectorID, reference.WorkID, reference.Attempt, reference.LeaseToken, 2*time.Second)
	return time.Now().UTC().Add(2 * time.Second), err
}

func (c directCollectorControlClient) UploadChunk(ctx context.Context, chunk collectorruntime.ResultChunk) error {
	_, err := c.store.UploadResultChunk(ctx, c.collectorID, collectorcontrol.ResultChunk{
		LeaseRef: collectorcontrol.LeaseRef{WorkID: chunk.WorkID, Attempt: chunk.Attempt, LeaseToken: chunk.LeaseToken},
		Index:    chunk.Index, Payload: chunk.Payload, SHA256: chunk.SHA256,
	})
	return err
}

func (c directCollectorControlClient) Finalize(ctx context.Context, finalization collectorruntime.Finalization) error {
	_, err := c.store.FinalizeResult(ctx, c.collectorID, collectorcontrol.ResultFinalization{
		LeaseRef: collectorcontrol.LeaseRef{WorkID: finalization.WorkID, Attempt: finalization.Attempt, LeaseToken: finalization.LeaseToken},
		RunID:    finalization.RunID, Status: finalization.Status, ChunkCount: finalization.ChunkCount,
		SHA256: finalization.SHA256, Bytes: finalization.Bytes,
	})
	return err
}

func TestM1AndM3ContractsRunThroughOutboundCollectorBoundary(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	collectionStore, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	controlStore, err := storepg.NewCollectorControlStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("remote-%d", time.Now().UnixNano())
	clusterID := domain.ClusterID("cluster-" + suffix)
	sourceID := domain.SourceID("source-" + suffix)
	collectorID := domain.CollectorID("collector-" + suffix)
	if err := collectionStore.EnsureSource(ctx, clusterID, "Remote acceptance cluster", sourceID, "Remote Prometheus"); err != nil {
		t.Fatal(err)
	}
	caCertificate, caKey := createTestCA(t, time.Now().UTC())
	issuer, err := collectorcontrol.NewCAIssuer(caCertificate, caKey, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := collectorcontrol.NewIdentityService(
		controlStore, issuer, identityTestClock{now: time.Now().UTC()},
		&identityTestIDs{values: []string{"bootstrap-" + suffix, string(collectorID)}}, rand.Reader, 10*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := identityService.CreateBootstrapKey(ctx, clusterID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	collectorPrivateKey, collectorCSR := createCollectorCSR(t)
	enrollment, err := identityService.Enroll(ctx, collectorcontrol.EnrollmentRequest{
		BootstrapToken: bootstrap.Token, CSRPEM: collectorCSR,
		Metadata: collectorcontrol.CollectorMetadata{
			DisplayName: "Remote acceptance collector", Version: "m2-test", BuildCommit: "test",
			ProtocolMin: 1, ProtocolMax: 1, OperatingSystem: "linux", Architecture: "amd64",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	controlTransport, err := collectorcontrol.NewTransport(identityService, controlStore, controlStore, controlStore, controlStore, identityTestClock{now: time.Now().UTC()}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientCAPool := x509.NewCertPool()
	if !clientCAPool.AppendCertsFromPEM(caCertificate) {
		t.Fatal("collector CA was not parseable")
	}
	controlServer := httptest.NewUnstartedServer(controlTransport)
	controlServer.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: clientCAPool}
	controlServer.StartTLS()
	defer controlServer.Close()
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(collectorPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCertificate, err := tls.X509KeyPair(
		append(append([]byte(nil), enrollment.Identity.CertificatePEM...), enrollment.Identity.CAChainPEM...),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	httpClient := controlServer.Client()
	httpTransport := httpClient.Transport.(*http.Transport).Clone()
	httpTransport.TLSClientConfig = httpTransport.TLSClientConfig.Clone()
	httpTransport.TLSClientConfig.MinVersion = tls.VersionTLS13
	httpTransport.TLSClientConfig.Certificates = []tls.Certificate{clientCertificate}
	httpClient.Transport = httpTransport
	protocolClient, err := collectorruntime.NewHTTPClient(controlServer.URL, httpClient, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocolClient.Heartbeat(ctx, collectorruntime.Heartbeat{
		CollectorID: collectorID, Version: "m2-test", BuildCommit: "test",
		Capabilities: []collectorruntime.Capability{
			{Name: string(domain.QueryGPUUtilization), Version: "1"},
			{Name: string(domain.QueryGPUXID), Version: "1"},
		},
		SourceHealth: []collectorruntime.SourceHealth{{SourceID: sourceID, Availability: "UNKNOWN", CheckedAt: time.Now().UTC()}},
	}); err != nil {
		t.Fatalf("authenticated heartbeat failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	xidPayload := fmt.Sprintf(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"DCGM_FI_DEV_XID_ERRORS","Hostname":"comp001","gpu":"3","UUID":"GPU-synthetic","err_code":"79"},"value":[%d,"79"]}]}}`, now.Unix())
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(request.URL.Query().Get("query"), "DCGM_FI_DEV_XID_ERRORS") {
			_, _ = fmt.Fprint(w, xidPayload)
			return
		}
		_, _ = fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"DCGM_FI_DEV_GPU_UTIL","Hostname":"comp001","gpu":"0"},"value":[%d,"42.5"]}]}}`, now.Unix())
	}))
	defer upstream.Close()
	prometheusClient, err := adapter.NewClient(adapter.Config{BaseURL: upstream.URL, Timeout: time.Second, MaxBytes: 1 << 20, MaxSeries: 100})
	if err != nil {
		t.Fatal(err)
	}
	clock := platform.SystemClock{}
	localExecutor, err := prometheusexecution.New(prometheusClient, clock, platform.RandomIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := collectorruntime.OpenJournal(t.TempDir()+"/attempts.json", clock)
	if err != nil {
		t.Fatal(err)
	}
	collectorRuntime, err := collectorruntime.NewRuntime(collectorruntime.RuntimeConfig{
		CollectorID: collectorID, SourceID: sourceID, Version: "m2-test", BuildCommit: "test",
		Capabilities: []string{string(domain.QueryGPUUtilization), string(domain.QueryGPUXID)}, HeartbeatInterval: time.Second,
		ClaimWait: 100 * time.Millisecond, RenewInterval: 500 * time.Millisecond,
		BackoffMinimum: 10 * time.Millisecond, BackoffMaximum: 50 * time.Millisecond,
	}, protocolClient, localExecutor, journal, clock)
	if err != nil {
		t.Fatal(err)
	}
	runtimeContext, stopRuntime := context.WithCancel(ctx)
	runtimeDone := make(chan error, 1)
	go func() { runtimeDone <- collectorRuntime.Run(runtimeContext) }()
	defer func() {
		stopRuntime()
		<-runtimeDone
	}()

	remoteExecutor, err := application.NewRemoteCollectionExecutor(controlStore, clock, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := application.NewCollector(remoteExecutor, collectionStore, clock, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	task := domain.CollectionTask{
		RunID: domain.RunID("run-" + suffix), ClusterID: clusterID, SourceID: sourceID,
		Query: domain.QueryGPUUtilization, ScheduledFor: now, Deadline: now.Add(10 * time.Second),
		MaxSeries: 100, MaxBytes: 1 << 20, IdempotencyKey: "remote-acceptance/" + suffix,
	}
	outcome, err := collector.Collect(ctx, task)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Result.Status != domain.ResultSucceeded || len(outcome.Result.Observations) != 1 || outcome.Result.Observations[0].Value != 42.5 {
		t.Fatalf("remote result=%+v", outcome.Result)
	}
	var runs, observations, ingestions, projections int
	if err := pool.QueryRow(ctx, `
		SELECT
		  (SELECT count(*) FROM collection_runs WHERE run_id=$1),
		  (SELECT count(*) FROM observations WHERE run_id=$1),
		  (SELECT count(*) FROM collector_result_ingestions WHERE run_id=$1),
		  (SELECT count(*) FROM current_projections WHERE observation_id IN (SELECT observation_id FROM observations WHERE run_id=$1))`, task.RunID).Scan(&runs, &observations, &ingestions, &projections); err != nil {
		t.Fatal(err)
	}
	if runs != 1 || observations != 1 || ingestions != 1 || projections != 1 {
		t.Fatalf("runs=%d observations=%d ingestions=%d projections=%d", runs, observations, ingestions, projections)
	}

	// M3 acceptance: reconstruct a known XID incident through the same outbound
	// collector path, then retain its exact raw source response and provenance.
	xidTask := domain.CollectionTask{
		RunID: domain.RunID("xid-run-" + suffix), ClusterID: clusterID, SourceID: sourceID,
		Query: domain.QueryGPUXID, Node: "comp001", ScheduledFor: now, Deadline: now.Add(10 * time.Second),
		MaxSeries: 100, MaxBytes: 1 << 20, IdempotencyKey: "m3-xid-acceptance/" + suffix,
	}
	xidOutcome, err := collector.Collect(ctx, xidTask)
	if err != nil {
		t.Fatal(err)
	}
	if xidOutcome.Result.Status != domain.ResultSucceeded || len(xidOutcome.Result.Observations) != 1 {
		t.Fatalf("unexpected XID collection result: %+v", xidOutcome.Result)
	}
	xidObservation := xidOutcome.Result.Observations[0]
	if xidObservation.Metric != "DCGM_FI_DEV_XID_ERRORS" || xidObservation.Value != 79 || xidObservation.EntityKey != "node/comp001/gpu/3" {
		t.Fatalf("unexpected normalized XID observation: %+v", xidObservation)
	}
	signals, err := application.ProjectGPUHealth(xidOutcome.Result, xidOutcome.Result.CompletedAt, application.DefaultGPUHealthThresholds())
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 1 || signals[0].Type != domain.HealthSignalXID || signals[0].Severity != domain.HealthSeverityCritical || len(signals[0].Evidence) != 1 || signals[0].Evidence[0] != xidObservation.ID {
		t.Fatalf("unexpected XID health signals: %+v", signals)
	}

	artifactReference, err := domain.NewArtifactReference(
		domain.ChecksumSHA256([]byte(xidPayload)), int64(len(xidPayload)), "application/json",
		domain.ArtifactUncompressed, "dcgm-prometheus-v1",
		domain.RedactionSummary{PolicyVersion: "synthetic-v1"}, domain.ArtifactRetentionStandard,
	)
	if err != nil {
		t.Fatal(err)
	}
	target := domain.EvidenceTarget{Kind: domain.EvidenceTargetGPU, ID: domain.EvidenceTargetID(xidObservation.EntityKey)}
	envelope, err := domain.CreateEvidenceEnvelope(domain.NewEvidenceEnvelope{
		ID: domain.EvidenceID("evidence-" + suffix), SchemaVersion: domain.EvidenceSchemaVersion,
		ClusterID: clusterID, Status: domain.EvidenceComplete,
		Source: domain.EvidenceSourceReference{
			SourceID: sourceID, RunID: xidTask.RunID, Operation: domain.EvidenceOperationID(domain.QueryGPUXID),
			DefinitionVersion: "1", Reference: domain.EvidenceSourceLocator(xidObservation.SourceReference),
		},
		TimeRange:   domain.EvidenceTimeRange{Start: xidObservation.ObservedAt, End: xidObservation.ObservedAt},
		CollectedAt: xidOutcome.Result.CompletedAt,
		Coverage:    domain.EvidenceCoverage{Expected: []domain.EvidenceTarget{target}, Covered: []domain.EvidenceTarget{target}},
		Artifact:    &artifactReference,
	})
	if err != nil {
		t.Fatal(err)
	}
	evidenceStore, err := storepg.NewEvidenceStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	artifactStore, err := artifacts.NewLocalStore(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	recorder, err := application.NewEvidenceRecorder(evidenceStore, artifactStore, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := recorder.Record(ctx, application.RecordEvidence{Envelope: envelope, RawArtifact: []byte(xidPayload)})
	if err != nil || recorded.PreviouslyRecorded || !recorded.ArtifactAvailable {
		t.Fatalf("record M3 evidence: outcome=%+v err=%v", recorded, err)
	}
	loaded, availability, found, err := evidenceStore.LoadEvidence(ctx, envelope.ID())
	if err != nil || !found || !loaded.Equal(envelope) || availability != domain.ArtifactAvailable {
		t.Fatalf("reconstruct M3 evidence: found=%v availability=%s err=%v", found, availability, err)
	}
	raw, err := artifactStore.Read(ctx, artifactReference)
	if err != nil || string(raw) != xidPayload {
		t.Fatalf("read M3 raw evidence: bytes=%d err=%v", len(raw), err)
	}
}

func integrationDatabaseURL(t *testing.T) string {
	t.Helper()
	value := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if value == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated test database")
	}
	return value
}
