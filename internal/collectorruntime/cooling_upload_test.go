package collectorruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func coolingSpoolForTest(t *testing.T, at time.Time, client *HTTPClient) coolingSpool {
	hash := domain.ChecksumSHA256([]byte("profile")).String()
	profile := domain.CoolingUploadProfile{
		Version: 2, ProfileID: "test", Revision: 1, CollectorID: "c", ClusterID: "cluster", SourceID: "source",
		InventoryRevision: "inventory", StartsAt: at.Add(-time.Hour), EndsAt: at.Add(time.Hour),
		Assets: []domain.CoolingUploadAsset{{NodeID: "node", GPUUUID: "GPU-a"}},
	}
	return coolingSpool{prometheusSpool: prometheusSpool{
		dir: t.TempDir(), client: client, logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, profile: profile, hash: hash}
}

type countedCoolingExecutor struct{ calls atomic.Int32 }

func (e *countedCoolingExecutor) ExecuteCooling(_ context.Context, _ domain.CoolingUploadProfile, task domain.CollectionTask) domain.CollectionResult {
	e.calls.Add(1)
	return domain.CollectionResult{Task: task, Status: domain.ResultPartial, StartedAt: task.ScheduledFor, CompletedAt: task.ScheduledFor,
		Failures: []domain.CollectionFailure{{Code: domain.FailurePartialData, Message: "missing points"}}}
}

func TestCoolingSpoolRetentionAndImmutableReplay(t *testing.T) {
	var mu sync.Mutex
	var payloads [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != domain.CoolingUploadPath || r.Header.Get(protocolHeader) != "2" {
			t.Errorf("unexpected cooling transport %s %s %s", r.Method, r.URL.Path, r.Header.Get(protocolHeader))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		mu.Lock()
		defer mu.Unlock()
		payloads = append(payloads, body)
		switch len(payloads) {
		case 1:
			w.WriteHeader(http.StatusServiceUnavailable)
		case 2:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusConflict)
		}
	}))
	defer server.Close()
	client, err := NewHTTPClient(server.URL, server.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	slot := now.UTC().Truncate(domain.CoolingUploadInterval)
	spool := coolingSpoolForTest(t, slot, client)
	old := coolingSpoolFilename(slot.Add(-time.Hour).Unix(), 0, spool.hash)
	foreign := coolingSpoolFilename(slot.Unix(), 0, domain.ChecksumSHA256([]byte("other revision")).String())
	for _, name := range []string{old, foreign} {
		if err := spool.save(name, []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	executor := &countedCoolingExecutor{}
	if err := spool.collect(t.Context(), executor, slot); err != nil {
		t.Fatal(err)
	}
	if err := spool.flush(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(spool.dir, old)); !os.IsNotExist(err) {
		t.Fatalf("expired report remains: %v", err)
	}
	if err := spool.collect(t.Context(), executor, slot); err != nil {
		t.Fatal(err)
	}
	if err := spool.flush(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(payloads) != 3 || !bytes.Equal(payloads[0], payloads[1]) {
		t.Fatalf("replayed payloads differ or out-of-scope payload attempted: %q", payloads)
	}
	for _, body := range payloads {
		var report domain.CoolingUploadReport
		if err := json.Unmarshal(body, &report); err != nil || report.Validate(spool.profile, spool.hash, now) != nil {
			t.Fatalf("invalid report was sent: %s", body)
		}
	}
	entries, err := spool.entries()
	if err != nil || len(entries) != 1 || entries[0].Name() != foreign {
		t.Fatalf("ready reports were not released or another profile was removed: %v %v", entries, err)
	}
}

func TestCoolingSpoolCapSkipsSourceReadsAndBoundsRetryBatch(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client, err := NewHTTPClient(server.URL, server.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	slot := time.Now().UTC().Truncate(domain.CoolingUploadInterval)
	spool := coolingSpoolForTest(t, slot, client)
	for index := range coolingSpoolMaxReports {
		prior := slot.Add(-time.Duration(index/2) * domain.CoolingUploadInterval)
		name := coolingSpoolFilename(prior.Unix(), index%2, spool.hash)
		if err := os.WriteFile(filepath.Join(spool.dir, name), []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	executor := &countedCoolingExecutor{}
	if err := spool.collect(t.Context(), executor, slot); err != nil || executor.calls.Load() != 0 {
		t.Fatalf("full spool ran the source: %v calls=%d", err, executor.calls.Load())
	}
	if err := spool.flush(t.Context(), slot); err != nil || calls.Load() != coolingReplayBatch {
		t.Fatalf("retry bound = %d, error = %v", calls.Load(), err)
	}
}

func TestProbeCoolingUploadRequiresScopedRejection(t *testing.T) {
	for _, permitted := range []bool{false, true} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			if r.Method != http.MethodPost || r.URL.Path != domain.CoolingUploadPath || r.Header.Get(protocolHeader) != "2" || string(raw) != `{}` {
				t.Errorf("unexpected readiness request %s %s %q", r.Method, r.URL, raw)
			}
			if !permitted {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"type":"urn:sherlock:collector:error:invalid_argument","title":"cooling report is invalid","status":400,"code":"INVALID_ARGUMENT","correlation_id":"test"}`)
		}))
		client, err := NewHTTPClient(server.URL, server.Client(), time.Second)
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		err = client.ProbeCoolingUpload(t.Context())
		server.Close()
		if (err == nil) != permitted {
			t.Fatalf("readiness for permitted=%t returned %v", permitted, err)
		}
	}
}

func TestCoolingSpoolCanCollectWhileDeliveryWaits(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
		case <-release:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	defer close(release)

	client, err := NewHTTPClient(server.URL, server.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	slot := now.UTC().Truncate(domain.CoolingUploadInterval)
	spool := coolingSpoolForTest(t, slot, client)
	executor := &countedCoolingExecutor{}
	if err := spool.collect(t.Context(), executor, slot.Add(-domain.CoolingUploadInterval)); err != nil {
		t.Fatal(err)
	}
	flushDone := make(chan error, 1)
	flushCtx, stopFlush := context.WithCancel(t.Context())
	defer stopFlush()
	go func() { flushDone <- spool.flush(flushCtx, now) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("delivery did not begin")
	}
	collectDone := make(chan error, 1)
	go func() { collectDone <- spool.collect(t.Context(), executor, slot) }()
	select {
	case err := <-collectDone:
		if err != nil || executor.calls.Load() != 4 {
			t.Fatalf("source collection failed during replay: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("delivery blocked acquisition")
	}
	stopFlush()
	if err := <-flushDone; err != nil {
		t.Fatal(err)
	}
}

func TestExpiredCoolingRuntimePrunesWithoutSampling(t *testing.T) {
	slot := time.Now().UTC().Truncate(domain.CoolingUploadInterval).Add(-time.Hour)
	spool := coolingSpoolForTest(t, slot, nil)
	spool.profile.EndsAt = slot.Add(domain.CoolingUploadInterval)
	if err := os.Chmod(spool.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	name := coolingSpoolFilename(slot.Unix(), 0, spool.hash)
	if err := spool.save(name, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	executor := &countedCoolingExecutor{}
	if err := RunCoolingUpload(t.Context(), executor, spool.client, spool.logger, spool.dir, spool.profile, spool.hash); err != nil {
		t.Fatal(err)
	}
	if executor.calls.Load() != 0 {
		t.Fatal("expired cooling profile performed new source reads")
	}
	if _, err := os.Stat(filepath.Join(spool.dir, name)); !os.IsNotExist(err) {
		t.Fatalf("expired report remains: %v", err)
	}
}

func TestCoolingReplaySkipsDefinitivelyRejectedPreregistration(t *testing.T) {
	for _, edgeResponse := range []string{"", "html", "scope denial", "wrong correlation"} {
		name := edgeResponse
		if name == "" {
			name = "preregistration rejection"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Now()
			fresh := now.UTC().Truncate(domain.CoolingUploadInterval)
			old := fresh.Add(-domain.CoolingUploadInterval)
			registered := old.Add(time.Second)
			spool := coolingSpoolForTest(t, fresh, nil)

			var attempts, accepted atomic.Int32
			var simulateEdge atomic.Bool
			simulateEdge.Store(edgeResponse != "")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				var report domain.CoolingUploadReport
				if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if err := report.Validate(spool.profile, spool.hash, now); err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if report.Result.Task.ScheduledFor.After(registered) {
					accepted.Add(1)
					w.WriteHeader(http.StatusNoContent)
					return
				}
				problem := coolingUploadProblem{
					Type: "urn:sherlock:collector:error:forbidden", Title: "cooling report lacks active enrollment",
					Code: "FORBIDDEN", Status: http.StatusForbidden, CorrelationID: r.Header.Get(correlationHeader),
				}
				if simulateEdge.Load() {
					switch edgeResponse {
					case "html":
						w.Header().Set("Content-Type", "text/html")
						w.WriteHeader(http.StatusForbidden)
						_, _ = io.WriteString(w, "<html>Access denied</html>")
						return
					case "scope denial":
						problem.Title = "collector is outside the cooling upload scope"
					case "wrong correlation":
						problem.CorrelationID = "edge-generated"
					}
				}
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(problem)
			}))
			defer server.Close()
			client, err := NewHTTPClient(server.URL, server.Client(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			spool.client = client
			executor := &countedCoolingExecutor{}
			for _, slot := range []time.Time{old, fresh} {
				if err := spool.collect(t.Context(), executor, slot); err != nil {
					t.Fatal(err)
				}
			}
			if err := spool.flush(t.Context(), now); err != nil {
				t.Fatal(err)
			}
			var deferred int32
			if edgeResponse != "" {
				entries, err := spool.entries()
				if err != nil || len(entries) != 4 || attempts.Load() != 1 || accepted.Load() != 0 {
					t.Fatalf("unconfirmed rejection did not preserve queue: reports=%d attempts=%d accepted=%d err=%v", len(entries), attempts.Load(), accepted.Load(), err)
				}
				deferred = 1
				simulateEdge.Store(false)
				if err := spool.flush(t.Context(), now); err != nil {
					t.Fatal(err)
				}
			}
			entries, err := spool.entries()
			if err != nil || len(entries) != 0 || attempts.Load() != deferred+coolingReplayBatch || accepted.Load() != 2 {
				t.Fatalf("eligible reports failed to clear immediately after preregistration: reports=%d attempts=%d accepted=%d err=%v", len(entries), attempts.Load(), accepted.Load(), err)
			}
			if err := spool.flush(t.Context(), now); err != nil || attempts.Load() != deferred+coolingReplayBatch {
				t.Fatalf("terminal reports replayed: attempts=%d err=%v", attempts.Load(), err)
			}
		})
	}
}
