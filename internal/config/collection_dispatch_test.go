package config

import (
	"encoding/json"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestCollectionDispatchConfiguration(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "postgres://fixture")
	t.Setenv("SHERLOCK_COLLECTION_EXECUTOR", "remote")
	t.Setenv("SHERLOCK_COLLECTION_RESERVATION_ENABLED", "")
	t.Setenv("SHERLOCK_COLLECTION_DISPATCH_FLOOR", "")
	t.Setenv("SHERLOCK_COLLECTION_DISPATCH_PERIOD", "")
	t.Setenv("SHERLOCK_DURABLE_EXECUTIONS", "")
	cfg, err := LoadWorker()
	if err != nil || cfg.CollectionReservationEnabled || cfg.CollectionDispatchFloor != 1 || cfg.CollectionDispatchPeriod != 2 {
		t.Fatalf("defaults: %+v %v", cfg, err)
	}
	t.Setenv("SHERLOCK_COLLECTION_RESERVATION_ENABLED", "true")
	if _, err = LoadWorker(); err == nil {
		t.Fatal("accepted missing collector enrollment")
	}
	grant := domain.DurableExecution{ScheduleKey: domain.ScheduleKey{ClusterID: "c", SourceID: "s", Operation: domain.OperationPrometheusGPUUtilization}, Revision: 1, CollectorID: "collector"}
	encoded, _ := json.Marshal([]domain.DurableExecution{grant})
	t.Setenv("SHERLOCK_DURABLE_EXECUTIONS", string(encoded))
	if _, err = LoadWorker(); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"0", "2"}, {"-1", "2"}, {"2", "2"}, {"3", "2"}, {"1", "1"}, {"1", "101"}, {"x", "2"}, {"1", "x"}} {
		t.Setenv("SHERLOCK_COLLECTION_DISPATCH_FLOOR", pair[0])
		t.Setenv("SHERLOCK_COLLECTION_DISPATCH_PERIOD", pair[1])
		if _, err = LoadWorker(); err == nil {
			t.Fatalf("accepted oversubscribed/invalid policy %v", pair)
		}
	}
	t.Setenv("SHERLOCK_COLLECTION_DISPATCH_FLOOR", "1")
	t.Setenv("SHERLOCK_COLLECTION_DISPATCH_PERIOD", "2")
	t.Setenv("SHERLOCK_COLLECTION_EXECUTOR", "inprocess")
	t.Setenv("SHERLOCK_PROMETHEUS_URL", "http://fixture")
	if _, err = LoadWorker(); err == nil {
		t.Fatal("accepted in-process reservation")
	}
}
