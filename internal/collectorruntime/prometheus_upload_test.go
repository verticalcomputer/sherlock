package collectorruntime

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestPrometheusSpoolReplaysExactPayloadAndExpiresOldReports(t *testing.T) {
	var mu sync.Mutex
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != domain.PrometheusUploadPath {
			t.Errorf("unexpected upload target %s %s", r.Method, r.URL.Path)
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		mu.Lock()
		defer mu.Unlock()
		requests = append(requests, string(raw))
		switch len(requests) {
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
	dir := t.TempDir()
	spool := prometheusSpool{dir: dir, client: client, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	now := time.Unix(1800000000, 0)
	old := "001799998800-0.json"
	first := "001800000000-0.json"
	second := "001800000000-1.json"
	for _, name := range []string{old, first, second} {
		if err := spool.save(name, []byte(`{"name":"`+name+`"}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := spool.save(first, []byte(`{"replacement":"must never overwrite a pending slot"}`)); err != nil {
		t.Fatal(err)
	}
	if err := spool.flush(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, old)); !os.IsNotExist(err) {
		t.Fatalf("expired report was retained: %v", err)
	}
	mu.Lock()
	got := len(requests)
	mu.Unlock()
	if got != 1 {
		t.Fatalf("attempts during temporary outage = %d, want 1", got)
	}
	// A new runtime instance replays the saved files after recovery.
	reopened := prometheusSpool{dir: dir, client: client, logger: spool.logger}
	if err := reopened.flush(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("acknowledged and conflicted reports should be removed: %v %v", entries, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 3 || requests[0] != requests[1] ||
		requests[0] != `{"name":"`+first+`"}` || requests[2] != `{"name":"`+second+`"}` {
		t.Fatalf("replayed payloads = %q", requests)
	}
}
