package linuxtelemetry

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

type fakeReader struct {
	bodies  map[string]string
	errors  map[string]error
	stats   rootStats
	rootErr error
	calls   int
}

func (r *fakeReader) proc(name string, _ int) ([]byte, error) {
	r.calls++
	return []byte(r.bodies[name]), r.errors[name]
}
func (r *fakeReader) root(context.Context) (rootStats, error) { r.calls++; return r.stats, r.rootErr }

var testAt = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func hostReader() *fakeReader {
	return &fakeReader{bodies: map[string]string{"meminfo": "MemTotal: 1024 kB\nMemAvailable: 512 kB\nUnrelated: 23 kB\n", "loadavg": "1.25 0.50 0.75 1/12 42\n", "uptime": "123.50 234.00\n"}, errors: map[string]error{}}
}
func frame(t *testing.T, r *fakeReader, profile string) telemetry.SourceFrame {
	t.Helper()
	c := &Collector{reader: r, now: func() time.Time { return testAt }}
	f, err := c.Collect(context.Background(), profile, "source-a", "cluster-a", "node-a", "sample-a", testAt)
	if err != nil {
		t.Fatal(err)
	}
	b := telemetry.NodeBatch{ProtocolVersion: 1, Key: telemetry.BatchKey{ClusterID: "cluster-a", NodeID: "node-a", EnrollmentID: "enrollment-a", SessionEpoch: "1", SessionID: "session-a", Sequence: "1"}, EnrollmentRevision: 1, InventoryRevisionID: "inventory-a", BootID: "boot-a", SigningKeyID: "key-a", AgentVersion: "linux-source-test", BuildSHA256: strings.Repeat("a", 64), CreatedAt: testAt, Sources: []telemetry.SourceFrame{f}}
	if telemetry.ValidateNodeBatch(b) != nil {
		t.Fatal("collector violated closed schema")
	}
	return f
}
func field(f telemetry.SourceFrame, metric string) telemetry.FieldSupport {
	for _, v := range f.Fields {
		if v.Metric == metric {
			return v
		}
	}
	return telemetry.FieldSupport{}
}

func TestHostExactValuesAndNoProcessPayload(t *testing.T) {
	r := hostReader()
	f := frame(t, r, telemetry.LinuxHostProfile)
	if f.Status != "SUCCEEDED" || f.Coverage.Returned != 6 || r.calls != 3 {
		t.Fatal("coverage", f)
	}
	if f.Records[0].Value.Unsigned != "1048576" || f.Records[1].Value.Unsigned != "524288" || *f.Records[2].Value.Float != 1.25 || *f.Records[5].Value.Float != 123.5 {
		t.Fatal("units or values")
	}
	for _, v := range f.Records {
		if !v.ObservedAt.Equal(testAt) || v.Reset != "not_applicable" {
			t.Fatal("timestamp/semantics")
		}
	}
}
func TestHostReadFailuresStayPartialAndMissingIsNotZero(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		err        error
		want       string
	}{
		{"missing", "MemTotal: 1024 kB\n", nil, "MISSING"},
		{"overflow", "MemTotal: 1024 kB\nMemAvailable: 18446744073709551615 kB\n", nil, "SOURCE_FAILED"},
		{"wrong_unit", "MemTotal: 1024 kB\nMemAvailable: 2 MB\n", nil, "SOURCE_FAILED"},
		{"duplicate", "MemTotal: 1024 kB\nMemAvailable: 2 kB\nMemAvailable: 3 kB\n", nil, "SOURCE_FAILED"},
		{"inconsistent", "MemTotal: 1 kB\nMemAvailable: 2 kB\n", nil, "SOURCE_FAILED"},
		{"denied", "", os.ErrPermission, "ACCESS_DENIED"},
		{"oversized", strings.Repeat("x", (64<<10)+1), nil, "SOURCE_FAILED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := hostReader()
			r.bodies["meminfo"] = tc.body
			r.errors["meminfo"] = tc.err
			f := frame(t, r, telemetry.LinuxHostProfile)
			v := field(f, "host.memory.available_bytes")
			if v.State != "UNKNOWN" || v.Reason != tc.want || f.Status != "PARTIAL" || f.Coverage.Complete {
				t.Fatal("failure hidden", f)
			}
			for _, record := range f.Records {
				if record.Metric == v.Metric {
					t.Fatal("manufactured value")
				}
			}
		})
	}
	r := hostReader()
	r.bodies["meminfo"] = "MemTotal: 1024 kB\nMemAvailable: 0 kB\n"
	if frame(t, r, telemetry.LinuxHostProfile).Records[1].Value.Unsigned != "0" {
		t.Fatal("observed zero lost")
	}
}
func TestNonfiniteAndMalformedFloatIsUnknown(t *testing.T) {
	for _, value := range []string{"NaN", "+Inf", "-1", "1e999", "no"} {
		r := hostReader()
		r.bodies["loadavg"] = value + " 2 3"
		r.bodies["uptime"] = value
		f := frame(t, r, telemetry.LinuxHostProfile)
		if field(f, "host.load.one").Reason != "SOURCE_FAILED" || field(f, "host.uptime_seconds").Reason != "SOURCE_FAILED" || len(f.Records) != 4 {
			t.Fatal(value, f)
		}
	}
}
func TestRootExactLargeIntegersReservedSpaceAndUnknownInodes(t *testing.T) {
	r := &fakeReader{stats: rootStats{Total: 1 << 60, Free: 100, Available: 80, Inodes: 1000, FreeInodes: 500}}
	f := frame(t, r, telemetry.LinuxRootProfile)
	if f.Status != "SUCCEEDED" || f.Records[0].Value.Unsigned != strconv.FormatUint(1<<60, 10) || f.Records[1].Value.Unsigned != "100" || f.Records[2].Value.Unsigned != "80" {
		t.Fatal("precision/reserved blocks")
	}
	r.stats.Inodes = 0
	r.stats.FreeInodes = 0
	f = frame(t, r, telemetry.LinuxRootProfile)
	if len(f.Records) != 3 || field(f, "filesystem.root.total_inodes").Reason != "MISSING" {
		t.Fatal("zero inode total asserted")
	}
	for _, stats := range []rootStats{{Total: 1, Free: 2}, {Total: 2, Free: 1, Available: 2}, {Total: 2, Inodes: 1, FreeInodes: 2}, {}} {
		r.stats = stats
		f = frame(t, r, telemetry.LinuxRootProfile)
		if len(f.Records) != 0 || f.Status != "FAILED" {
			t.Fatal("inconsistent stats accepted")
		}
	}
	r.rootErr = errUnsupported
	f = frame(t, r, telemetry.LinuxRootProfile)
	if field(f, "filesystem.root.total_bytes").State != "NOT_SUPPORTED" {
		t.Fatal("unsupported hidden")
	}
}
func TestCancellationClockAndProfileRejectWithoutReads(t *testing.T) {
	r := hostReader()
	c := &Collector{reader: r, now: func() time.Time { return testAt.Add(-time.Second) }}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Collect(ctx, telemetry.LinuxHostProfile, "s", "c", "n", "p", testAt); !errors.Is(err, context.Canceled) || r.calls != 0 {
		t.Fatal("cancellation")
	}
	if _, err := c.Collect(context.Background(), telemetry.FixtureProfile, "s", "c", "n", "p", testAt); err == nil || r.calls != 0 {
		t.Fatal("unknown profile")
	}
	if _, err := c.Collect(context.Background(), telemetry.LinuxHostProfile, "s", "c", "n", "p", testAt); err == nil {
		t.Fatal("clock regression")
	}
}
