//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	prom "github.com/verticalcomputer/sherlock/internal/adapters/prometheus"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	execution "github.com/verticalcomputer/sherlock/internal/collectorexecution/prometheus"
	"github.com/verticalcomputer/sherlock/internal/collectorpop"
	"github.com/verticalcomputer/sherlock/internal/collectorruntime"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestPrometheusUploadThroughIsolatedAccess(t *testing.T) {
	dsn := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires an isolated migrated database")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	uploadPool := pool
	if uploadDSN := os.Getenv("SHERLOCK_TEST_UPLOAD_DATABASE_URL"); uploadDSN != "" {
		uploadPool, err = pgxpool.New(ctx, uploadDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer uploadPool.Close()
		var denied bool
		err = uploadPool.QueryRow(ctx, `SELECT NOT has_table_privilege(current_user,'collector_work_items','SELECT')
 AND NOT has_table_privilege(current_user,'collection_target_inventory','SELECT')`).Scan(&denied)
		if err != nil || !denied {
			t.Fatalf("upload role has legacy table access, err=%v", err)
		}
	}
	clock := platform.SystemClock{}
	now := clock.Now()
	slot := now.UTC().Truncate(time.Minute).Add(-time.Minute)
	suffix := fmt.Sprint(now.UnixNano())
	cluster := domain.ClusterID("access-cluster-" + suffix)
	source := domain.SourceID("access-source-" + suffix)
	collector := domain.CollectorID("access-head-" + suffix)
	admin, _ := storepg.NewCollectionStore(pool)
	if err := admin.EnsureSource(ctx, cluster, "Access fixture cluster", source, "Access fixture source"); err != nil {
		t.Fatal(err)
	}
	goodput, _ := storepg.NewGoodputStore(pool)
	var entities []domain.EntityIdentity
	for node := 1; node <= 10; node++ {
		name := domain.StableNodeID(fmt.Sprintf("fixture-comp%03d", node))
		entities = append(entities, domain.EntityIdentity{ClusterID: cluster, Kind: domain.EntityNode, NodeID: name})
		for gpu := 0; gpu < 8; gpu++ {
			id := domain.PhysicalGPUUUID(fmt.Sprintf("GPU-%03d-%d", node, gpu))
			entities = append(entities, domain.EntityIdentity{ClusterID: cluster, Kind: domain.EntityGPU, NodeID: name, PhysicalGPUUUID: id})
		}
	}
	earlier := slot.Add(-time.Hour)
	if _, err := goodput.RecordExpectedInventoryRevision(ctx, domain.InventoryRevision{
		ID: domain.InventoryRevisionID("access-revision-" + suffix), SchemaVersion: domain.InventoryContractSchemaVersion,
		ClusterID: cluster, SourceID: source, SourceAt: earlier, EffectiveAt: earlier, ObservedAt: earlier, Entities: entities,
	}); err != nil {
		t.Fatal(err)
	}
	caPEM, caKey := uploadFixtureCA(t, now)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("invalid fixture collector CA")
	}
	issuer, err := collectorcontrol.NewCAIssuer(caPEM, caKey, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controlAdmin, _ := storepg.NewCollectorControlStore(pool)
	identity, err := collectorcontrol.NewIdentityService(controlAdmin, issuer, clock, platform.RandomIDGenerator{}, rand.Reader, 5*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	enroll := func() tls.Certificate {
		t.Helper()
		key, csr := m15CollectorCSR(t)
		grant, err := identity.CreateBootstrapKey(ctx, cluster, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		issued, err := identity.Enroll(ctx, collectorcontrol.EnrollmentRequest{
			BootstrapToken: grant.Token, CSRPEM: csr,
			Metadata: collectorcontrol.CollectorMetadata{DisplayName: "fixture", Version: "dev", BuildCommit: "fixture",
				ProtocolMin: 1, ProtocolMax: 1, OperatingSystem: "linux", Architecture: "amd64"},
		})
		if err != nil {
			t.Fatal(err)
		}
		collector = issued.CollectorID
		block, _ := pem.Decode(issued.Identity.CertificatePEM)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatal("fixture collector certificate")
		}
		return tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key}
	}
	otherCert := enroll()
	clientCert := enroll()

	signing, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const (
		host     = "example.com"
		audience = "isolated-upload-audience"
		kid      = "fixture-key"
		id       = "fixture-service-id"
		secret   = "fixture-service-secret"
	)
	jwks := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cdn-cgi/access/certs" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": kid, "kty": "RSA", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(signing.N.Bytes()), "e": "AQAB",
		}}})
	}))
	defer jwks.Close()

	databaseAuth, _ := storepg.NewCollectorControlStore(uploadPool)
	store, _ := storepg.NewCollectionStore(uploadPool)
	newOrigin := func() *httptest.Server {
		t.Helper()
		auth, err := collectorcontrol.NewCloudflareAccessServiceTokenPoPAuthenticator(ctx, collectorcontrol.CloudflareAccessServiceTokenPoPConfig{
			Issuer: jwks.URL, Audience: audience, TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
			CollectorHostname: host, EnrollmentHostname: "enroll.example.com", CollectorRoots: roots,
			ReplayStore: databaseAuth, HTTPClient: jwks.Client(), Clock: clock,
		})
		if err != nil {
			t.Fatal(err)
		}
		h, err := collectorcontrol.NewPrometheusUploadHandler(databaseAuth, auth, store, clock, collector, cluster, source)
		if err != nil {
			t.Fatal(err)
		}
		return httptest.NewTLSServer(h)
	}
	origin := newOrigin()
	defer func() { origin.Close() }()
	var mu sync.Mutex
	var captured *http.Request
	edge := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("CF-Access-Client-Id") != id || r.Header.Get("CF-Access-Client-Secret") != secret {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		variant := r.Header.Get("X-Fixture-Variant")
		r.Header.Del("CF-Access-Client-Id")
		r.Header.Del("CF-Access-Client-Secret")
		r.Header.Del("Cf-Access-Jwt-Assertion")
		claims := jwt.RegisteredClaims{Issuer: jwks.URL, Audience: jwt.ClaimStrings{audience},
			IssuedAt: jwt.NewNumericDate(time.Now()), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}
		switch variant {
		case "wrong-audience":
			claims.Audience = jwt.ClaimStrings{"other-audience"}
		case "expired":
			claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid
		signed, err := token.SignedString(signing)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if variant == "bad-signature" {
			r.Header.Set(collectorpop.SignatureHeader, "invalid")
		}
		if variant != "missing-assertion" {
			r.Header.Set("Cf-Access-Jwt-Assertion", signed)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if variant == "tamper-body" && len(body) > 0 {
			body[len(body)-1] = ' '
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		mu.Lock()
		if captured == nil && variant == "" && r.URL.Path == domain.PrometheusUploadPath && !bytes.Equal(body, []byte("{}")) {
			captured = r.Clone(context.Background())
			captured.Body = io.NopCloser(bytes.NewReader(body))
		}
		upstream := origin
		mu.Unlock()
		target, _ := url.Parse(upstream.URL)
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.Transport = upstream.Client().Transport
		proxy.ServeHTTP(w, r)
	}))
	defer edge.Close()

	baseTransport := edge.Client().Transport.(*http.Transport).Clone()
	baseTransport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, edge.Listener.Addr().String())
	}
	makeClient := func(cert tls.Certificate, credential string) *http.Client {
		t.Helper()
		wrapper, err := collectorruntime.NewAccessServiceTokenPoPRoundTripper(baseTransport,
			collectorruntime.AccessServiceToken{ClientID: id, ClientSecret: credential}, cert)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Client{Transport: wrapper, Timeout: 5 * time.Second}
	}
	client := makeClient(clientCert, secret)
	probe, err := collectorruntime.NewHTTPClient("https://"+host, client, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := probe.ProbePrometheusUpload(ctx); err != nil {
		t.Fatalf("authenticated upload readiness: %v", err)
	}
	send := func(c *http.Client, path, variant string, payload []byte, code int) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+path, bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Sherlock-Protocol-Version", "1")
		request.Header.Set("X-Correlation-ID", fmt.Sprintf("fixture-%d", time.Now().UnixNano()))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Fixture-Variant", variant)
		response, err := c.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != code {
			raw, _ := io.ReadAll(response.Body)
			t.Fatalf("case=%q status=%d want=%d body=%s", variant, response.StatusCode, code, raw)
		}
	}

	// Use the same fixed query executor and actual mTLS-derived signing key as
	// the collector. The fixture controls its Prometheus response only.
	prometheus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			t.Errorf("unexpected Prometheus endpoint %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		query := r.URL.Query().Get("query")
		fields := map[string]string{
			"DCGM_FI_DEV_GPU_UTIL": "15", "DCGM_FI_DEV_XID_ERRORS": "0",
			"DCGM_FI_DEV_GPU_TEMP": "45", "DCGM_FI_DEV_MEMORY_TEMP": "55",
			"DCGM_FI_DEV_POWER_USAGE": "217.5",
			"DCGM_FI_DEV_FB_USED":     "78000", "DCGM_FI_DEV_FB_FREE": "2000", "DCGM_FI_DEV_FB_RESERVED": "480",
			"DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS": "0", "DCGM_FI_DEV_UNCORRECTABLE_REMAPPED_ROWS": "1",
		}
		for _, forbidden := range []string{"DCGM_FI_DEV_POWER_MGMT_LIMIT", "DCGM_FI_DEV_ECC_", "DCGM_FI_DEV_ROW_REMAP_FAILURE"} {
			if strings.Contains(query, forbidden) {
				t.Errorf("scheduled query includes unrequested field %q", forbidden)
			}
		}
		vector := make([]map[string]any, 0, 240)
		for _, e := range entities {
			if e.Kind != domain.EntityGPU {
				continue
			}
			appendSample := func(metric, value string) {
				labels := map[string]string{"Hostname": string(e.NodeID), "UUID": string(e.PhysicalGPUUUID)}
				if metric != "" {
					labels["__name__"] = metric
				}
				vector = append(vector, map[string]any{"metric": labels, "value": []any{slot.Unix(), value}})
			}
			if strings.HasPrefix(query, "count by") {
				appendSample("", "1")
			} else {
				for metric, value := range fields {
					if strings.Contains(query, metric) {
						appendSample(metric, value)
					}
				}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": vector}})
	}))
	defer prometheus.Close()
	sourceClient, err := prom.NewClient(prom.Config{BaseURL: prometheus.URL, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	// The replay uses a recent closed slot. Give the executor an active local
	// deadline, then restore the original task and the fixture evaluation times.
	executor, err := execution.NewUpload(sourceClient, clock, platform.RandomIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	var payload []byte
	var temperature domain.CollectionResult
	for _, q := range domain.PrometheusUploadQueries() {
		task := domain.PrometheusUploadTask(cluster, source, q, slot)
		runnable := task
		runnable.Deadline = now.Add(20 * time.Second)
		result := executor.Execute(ctx, runnable)
		if result.Status != domain.ResultSucceeded || len(result.Observations) != 80*max(1, len(domain.PrometheusUploadFields(q))) {
			t.Fatalf("fixture query %s returned %s and %d observations", q, result.Status, len(result.Observations))
		}
		result.Task, result.StartedAt, result.CompletedAt = task, slot, slot.Add(time.Second)
		for i := range result.Observations {
			result.Observations[i].CollectedAt = result.CompletedAt
		}
		raw, err := json.Marshal(domain.PrometheusReport{Version: domain.PrometheusUploadVersion, Result: result})
		if err != nil {
			t.Fatal(err)
		}
		send(client, domain.PrometheusUploadPath, "", raw, http.StatusNoContent)
		if q == domain.QueryGPUTemperature {
			temperature = result
		}
		if payload == nil {
			payload = raw
		}
	}
	send(client, domain.PrometheusUploadPath, "", payload, http.StatusNoContent)
	for _, variant := range []string{"missing-assertion", "wrong-audience", "expired", "tamper-body", "bad-signature"} {
		send(client, domain.PrometheusUploadPath, variant, payload, http.StatusUnauthorized)
	}
	send(makeClient(clientCert, "wrong-token"), domain.PrometheusUploadPath, "", payload, http.StatusForbidden)
	send(makeClient(otherCert, secret), domain.PrometheusUploadPath, "", payload, http.StatusForbidden)
	send(client, "/collector/v1/heartbeat", "", []byte("{}"), http.StatusNotFound)
	send(client, "/collector/v1/enroll", "", []byte("{}"), http.StatusNotFound)
	send(client, "/collector/v1/identity/renew", "", []byte("{}"), http.StatusNotFound)
	send(client, "/collector/v1/work/claim", "", []byte("{}"), http.StatusNotFound)

	// Restart the origin and replay the exact signed request and correlation ID
	// captured by the edge. Its nonce must still be rejected by PostgreSQL.
	restarted := newOrigin()
	mu.Lock()
	old := origin
	origin = restarted
	replay := captured
	mu.Unlock()
	old.Close()
	if replay == nil {
		t.Fatal("fixture failed to capture signed request")
	}
	replay.URL, _ = url.Parse(restarted.URL + domain.PrometheusUploadPath)
	replay.RequestURI = ""
	response, err := restarted.Client().Do(replay)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("persisted nonce replay status=%d", response.StatusCode)
	}
	var complete, work, attempts, nonces, fullMetrics int
	err = pool.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM evidence_envelopes WHERE cluster_id=$1 AND status='COMPLETE'
  AND jsonb_array_length(coverage_expected)=90 AND jsonb_array_length(coverage_covered)=90),
 (SELECT count(*) FROM collector_work_items WHERE cluster_id=$1),
 (SELECT count(*) FROM collector_work_attempts WHERE collector_id=$2),
 (SELECT count(*) FROM collector_request_nonces WHERE certificate_fingerprint=sha256($3::bytea)),
 (SELECT count(*) FROM (SELECT metric FROM observations WHERE cluster_id=$1
  GROUP BY metric HAVING count(*)=80 AND count(DISTINCT entity_key)=80) AS full_metrics)`,
		cluster, collector, clientCert.Certificate[0]).Scan(&complete, &work, &attempts, &nonces, &fullMetrics)
	if err != nil || complete != 7 || work != 0 || attempts != 0 || nonces != 9 || fullMetrics != 11 {
		t.Fatalf("complete=%d work=%d attempts=%d nonces=%d full metrics=%d err=%v", complete, work, attempts, nonces, fullMetrics, err)
	}
	// Substitute a duplicate reading for the other temperature field on one
	// GPU. The transport count remains 160, and all GPUs still appear, but
	// that field/GPU pair must not qualify as complete.
	partialSlot := slot.Add(-time.Minute)
	temperature.Task = domain.PrometheusUploadTask(cluster, source, domain.QueryGPUTemperature, partialSlot)
	temperature.StartedAt, temperature.CompletedAt = partialSlot, partialSlot.Add(time.Second)
	temperature.Observations[0].Metric = temperature.Observations[1].Metric
	for i := range temperature.Observations {
		temperature.Observations[i].ObservedAt = partialSlot
		temperature.Observations[i].CollectedAt = temperature.CompletedAt
	}
	raw, err := json.Marshal(domain.PrometheusReport{Version: domain.PrometheusUploadVersion, Result: temperature})
	if err != nil {
		t.Fatal(err)
	}
	send(client, domain.PrometheusUploadPath, "", raw, http.StatusNoContent)
	var status string
	var kept int
	err = pool.QueryRow(ctx, `SELECT r.status,(SELECT count(*) FROM observations o WHERE o.run_id=r.run_id)
 FROM collection_runs r WHERE r.run_id=$1`, temperature.Task.RunID).Scan(&status, &kept)
	if err != nil || status != "PARTIAL" || kept != 158 {
		t.Fatalf("duplicate temperature field: status=%s observations=%d err=%v", status, kept, err)
	}
	if tool := os.Getenv("SHERLOCK_TEST_UPLOAD_IDENTITY_TOOL"); tool != "" {
		exerciseOfflineUploadRotation(t, ctx, tool, dsn, pool, baseTransport, host, cluster, collector, clientCert, caPEM, caKey, id, secret)
	}

	t.Log("fixture Access service token and JWT, body proof, collector scope and durable nonce replay checks passed; 7 COMPLETE envelopes at 90/90, 11 metrics at 80/80, duplicate field remains PARTIAL; zero work and leases")
}

func exerciseOfflineUploadRotation(t *testing.T, ctx context.Context, tool, dsn string, pool *pgxpool.Pool,
	transport http.RoundTripper, host string, cluster domain.ClusterID, collector domain.CollectorID,
	original tls.Certificate, caPEM, caKey []byte, tokenID, tokenSecret string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"versions", "request", "issued"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	ca := write("ca.pem", caPEM)
	signingKey := write("ca-key.pem", caKey)
	caBlock, _ := pem.Decode(caPEM)
	pin := fmt.Sprintf("%x", sha256.Sum256(caBlock.Bytes))
	oldLeaf, err := x509.ParseCertificate(original.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	oldSerial := collectorruntime.UploadIdentitySerial(oldLeaf)
	oldCert := write("old.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: oldLeaf.Raw}))
	oldDER, err := x509.MarshalPKCS8PrivateKey(original.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := write("old-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: oldDER}))
	scope := []string{"-identity-dir", root, "-cluster", string(cluster), "-collector", string(collector), "-ca-sha256", pin}
	run := func(fail bool, op string, args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, tool, append(append([]string{op}, scope...), args...)...)
		issuerDSN := os.Getenv("SHERLOCK_TEST_UPLOAD_ISSUER_DATABASE_URL")
		if issuerDSN == "" {
			issuerDSN = dsn
		}
		cmd.Env = append(os.Environ(), "SHERLOCK_PROMETHEUS_ISSUER_DATABASE_URL="+issuerDSN)
		out, err := cmd.CombinedOutput()
		if (err != nil) != fail {
			t.Fatalf("identity %s: err=%v output=%s", op, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if got := run(false, "stage", "-cert", oldCert, "-key", oldKey, "-ca", ca); got != oldSerial {
		t.Fatalf("initial staged serial %q", got)
	}
	run(false, "switch", "-expect", "absent", "-target", oldSerial)
	state := collectorruntime.UploadIdentity{Directory: root, Cluster: string(cluster), Collector: string(collector), CAPin: pin}
	var selected, last string
	wrapper := collectorruntime.NewRotatingAccessServiceTokenPoP(transport, func() (tls.Certificate, error) {
		version := selected
		if version == "" {
			var err error
			version, err = state.Current()
			if err != nil {
				return tls.Certificate{}, err
			}
		}
		cert, err := state.Load(version, time.Now())
		if err == nil {
			last = collectorruntime.UploadIdentitySerial(cert.Leaf)
		}
		return cert, err
	}, func() (collectorruntime.AccessServiceToken, error) {
		return collectorruntime.AccessServiceToken{ClientID: tokenID, ClientSecret: tokenSecret}, nil
	})
	probe, err := collectorruntime.NewHTTPClient("https://"+host, &http.Client{Transport: wrapper}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	check := func(serial string) {
		t.Helper()
		if err := probe.ProbePrometheusUpload(ctx); err != nil || last != serial {
			t.Fatalf("signed readiness serial=%s want=%s: %v", last, serial, err)
		}
	}
	check(oldSerial)
	request := filepath.Join(root, "request", "csr.pem")
	key := filepath.Join(root, "request", "key.pem")
	run(false, "request", "-csr", request, "-key", key)
	leaf := filepath.Join(root, "issued", "cert.pem")
	issueArgs := []string{"-csr", request, "-ca", ca, "-ca-key", signingKey, "-expect", oldSerial, "-expect-sha256", fmt.Sprintf("%x", sha256.Sum256(oldLeaf.Raw))}
	run(false, "issue", append(issueArgs, "-cert", leaf)...)
	run(true, "issue", append(issueArgs, "-cert", filepath.Join(root, "issued", "stale.pem"))...)
	run(true, "stage", "-cert", leaf, "-key", oldKey, "-ca", ca)
	newSerial := run(false, "stage", "-cert", leaf, "-key", key, "-ca", ca)
	check(oldSerial)
	selected = newSerial
	check(newSerial) // verify through Access before touching the current pointer
	selected = ""
	run(true, "switch", "-expect", "absent", "-target", newSerial)
	run(false, "switch", "-expect", oldSerial, "-target", newSerial)
	check(newSerial) // same HTTP client, no restart
	run(false, "switch", "-expect", newSerial, "-target", oldSerial)
	check(oldSerial) // previous registered certificate survives its overlap
	if _, err := state.Load(oldSerial, oldLeaf.NotAfter.Add(time.Second)); err == nil {
		t.Fatal("expired rollback target accepted")
	}
	run(false, "switch", "-expect", oldSerial, "-target", newSerial)
	check(newSerial)
	var current string
	var superseded, overlap bool
	err = pool.QueryRow(ctx, `SELECT c.identity_serial, i.superseded_at IS NOT NULL,
			i.revoked_at IS NULL AND i.not_after>clock_timestamp()
		FROM collectors c JOIN collector_identities i USING(collector_id)
		WHERE c.collector_id=$1 AND i.certificate_serial=$2`, collector, oldSerial).Scan(&current, &superseded, &overlap)
	if err != nil || current != newSerial || !superseded || !overlap {
		t.Fatalf("unexpected renewal metadata: current=%s superseded=%v overlap=%v: %v", current, superseded, overlap, err)
	}
	t.Log("12-hour offline renewal through isolated PostgreSQL and Access PoP: pre-switch proof, live reload, rollback, re-forward, stale issuance and wrong-key rejection")
}

func uploadFixtureCA(t *testing.T, now time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated upload renewal CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
