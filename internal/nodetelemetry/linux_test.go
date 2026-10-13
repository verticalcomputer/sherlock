package nodetelemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

type syntheticLinuxCollector struct{ calls int }

func (c *syntheticLinuxCollector) Collect(_ context.Context, profile, source, cluster, node, prefix string, at time.Time) (telemetry.SourceFrame, error) {
	c.calls++
	f := telemetry.SourceFrame{SourceID: source, SchemaVersion: 1, ProfileID: profile, AdapterVersion: profile, StartedAt: at, CompletedAt: at, Status: "FAILED"}
	for _, field := range telemetry.ProfileFields(profile) {
		f.Fields = append(f.Fields, telemetry.FieldSupport{EntityKey: cluster + "/NODE/" + node + "//", Metric: field.Metric, State: "UNKNOWN", Reason: "ACCESS_DENIED"})
	}
	f.Coverage.Expected = int64(len(f.Fields))
	return f, nil
}

func TestLinuxFailedReadStillSealsAndReplayNeverRereads(t *testing.T) {
	c, g, at, _ := fixture(t)
	reader := &syntheticLinuxCollector{}
	c.LinuxSources = reader
	c.Scope.SourceProfiles = map[string]string{"source-a": telemetry.LinuxHostProfile}
	r := openRuntime(t, c)
	collect(t, r)
	batch := latestBatch(t, r)
	if reader.calls != 1 || batch.Sources[0].Status != "FAILED" || len(batch.Sources[0].Records) != 0 {
		t.Fatal("read failure not durable")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	*at = at.Add(30 * time.Second)
	r = openRuntime(t, c)
	g.failAfterCommit = true
	// The lifecycle is delivered first; one batch response is then lost.
	for i := 0; i < 3; i++ {
		_, err := r.DrainOnce(context.Background())
		if errors.Is(err, telemetry.ErrUnavailable) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	drain(t, r)
	if reader.calls != 1 || len(g.wires) != 1 {
		t.Fatal("replay reread source or duplicated batch")
	}
	original, _ := json.Marshal(batch)
	if !bytes.Equal(original, g.wires[batch.Key]) {
		t.Fatal("signed replay changed")
	}
	collect(t, r)
	if latestBatch(t, r).Key.Sequence != strconv.Itoa(2) || reader.calls != 2 {
		t.Fatal("same-boot continuity")
	}
}
func TestLinuxProfilesAreImmutableAndRequireCollector(t *testing.T) {
	c, _, _, _ := fixture(t)
	c.Scope.SourceProfiles = map[string]string{"source-a": telemetry.LinuxRootProfile}
	if _, err := Open(context.Background(), c); !errors.Is(err, ErrInvalid) {
		t.Fatal("Linux profile without collector")
	}
	c.LinuxSources = &syntheticLinuxCollector{}
	r := openRuntime(t, c)
	collect(t, r)
	_ = r.Close()
	c.Scope.SourceProfiles["source-a"] = telemetry.LinuxHostProfile
	if _, err := Open(context.Background(), c); err == nil {
		t.Fatal("old journal adopted changed profile")
	}
}
