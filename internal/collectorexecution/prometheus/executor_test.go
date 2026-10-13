package prometheus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	adapter "github.com/verticalcomputer/sherlock/internal/adapters/prometheus"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
)

const twoSeries = `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"up","instance":"node-a:9400"},"value":[1787133600,"1"]},{"metric":{"__name__":"up","instance":"node-b:9400"},"value":[1787133600,"1"]}]}}`

func executionTask() domain.CollectionTask {
	now := time.Now().UTC()
	return domain.CollectionTask{RunID: "run", ClusterID: "cluster", SourceID: "source", Query: domain.QuerySourceHealth, ScheduledFor: now, Deadline: now.Add(time.Second), MaxSeries: 100, MaxBytes: 10000, IdempotencyKey: "key"}
}

func TestScheduledExecutorUsesDistinctTaskLimitsConcurrently(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(twoSeries)) }))
	defer server.Close()
	client, err := adapter.NewClient(adapter.Config{BaseURL: server.URL, Timeout: time.Second, MaxSeries: 100, MaxBytes: 10000})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewScheduled(client, platform.SystemClock{}, platform.RandomIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, limit := range []string{"series", "bytes", "full"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			task := executionTask()
			if limit == "series" {
				task.MaxSeries = 1
			}
			if limit == "bytes" {
				task.MaxBytes = 64
			}
			result := executor.Execute(context.Background(), task)
			if limit == "full" {
				if result.Status != domain.ResultSucceeded {
					t.Errorf("full task: %+v", result)
				}
			} else if result.Status != domain.ResultFailed || len(result.Failures) != 1 || result.Failures[0].Code != domain.FailureResultLimit {
				t.Errorf("%s task did not enforce desired bounds: %+v", limit, result)
			}
		}()
	}
	wg.Wait()
	// The original client and a later wide task retain their configured bounds.
	if result, err := client.Instant(context.Background(), domain.QuerySourceHealth, "", time.Now()); err != nil || result.SeriesReturned != 2 {
		t.Fatalf("shared client was mutated: %+v %v", result, err)
	}
}

func TestScheduledDeadlineOverridesStartupWhileCollectorRetainsLocalCap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(40 * time.Millisecond):
			_, _ = w.Write([]byte(twoSeries))
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	client, err := adapter.NewClient(adapter.Config{BaseURL: server.URL, Timeout: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	scheduled, _ := NewScheduled(client, platform.SystemClock{}, platform.RandomIDGenerator{})
	local, _ := New(client, platform.SystemClock{}, platform.RandomIDGenerator{})
	if result := scheduled.Execute(context.Background(), executionTask()); result.Status != domain.ResultSucceeded {
		t.Fatalf("startup timeout overrode desired timeout: %+v", result)
	}
	if result := local.Execute(context.Background(), executionTask()); result.Status != domain.ResultFailed || len(result.Failures) != 1 || result.Failures[0].Code != domain.FailureDeadlineExceeded {
		t.Fatalf("collector local timeout was lost: %+v", result)
	}
	task := executionTask()
	task.Deadline = time.Now().Add(5 * time.Millisecond)
	if result := scheduled.Execute(context.Background(), task); result.Status != domain.ResultFailed || len(result.Failures) != 1 || result.Failures[0].Code != domain.FailureDeadlineExceeded {
		t.Fatalf("short desired deadline was ignored: %+v", result)
	}
}
