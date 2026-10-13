// Package linuxtelemetry collects fixed, read-only host source profiles. It
// never launches commands or inspects workloads, users or arbitrary paths.
package linuxtelemetry

import (
	"context"
	"errors"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

var errUnsupported = errors.New("source unsupported")
var errRead = errors.New("source read unavailable")

type rootStats struct{ Total, Free, Available, Inodes, FreeInodes uint64 }
type sourceReader interface {
	proc(string, int) ([]byte, error)
	root(context.Context) (rootStats, error)
}

type Collector struct {
	reader sourceReader
	now    func() time.Time
}

func New(now func() time.Time) *Collector {
	if now == nil {
		now = time.Now
	}
	return &Collector{reader: platformReader{}, now: now}
}

type observation struct {
	value  telemetry.Scalar
	reason string
}

func reason(err error) string {
	if errors.Is(err, errUnsupported) {
		return "UNSUPPORTED"
	}
	if errors.Is(err, os.ErrPermission) {
		return "ACCESS_DENIED"
	}
	if errors.Is(err, os.ErrNotExist) {
		return "MISSING"
	}
	return "SOURCE_FAILED"
}
func unsigned(n uint64) observation {
	return observation{value: telemetry.Scalar{Kind: "unsigned", Unsigned: strconv.FormatUint(n, 10)}, reason: "OBSERVED"}
}
func floating(n float64) observation {
	return observation{value: telemetry.Scalar{Kind: "float", Float: &n}, reason: "OBSERVED"}
}

func (c *Collector) Collect(ctx context.Context, profile, source, cluster, node, prefix string, at time.Time) (telemetry.SourceFrame, error) {
	if c == nil || c.reader == nil || c.now == nil || profile != telemetry.LinuxHostProfile && profile != telemetry.LinuxRootProfile || !telemetry.ValidIdentifier(source) || !telemetry.ValidIdentifier(prefix) || len(prefix) > 90 {
		return telemetry.SourceFrame{}, telemetry.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return telemetry.SourceFrame{}, err
	}
	identity, err := domain.CreateEntityIdentity(domain.EntityIdentity{ClusterID: domain.ClusterID(cluster), Kind: domain.EntityNode, NodeID: domain.StableNodeID(node)})
	if err != nil {
		return telemetry.SourceFrame{}, telemetry.ErrInvalid
	}
	values := map[string]observation{}
	if profile == telemetry.LinuxHostProfile {
		for _, name := range []string{"meminfo", "loadavg", "uptime"} {
			if err := ctx.Err(); err != nil {
				return telemetry.SourceFrame{}, err
			}
			body, err := c.reader.proc(name, 64<<10)
			if len(body) > 64<<10 {
				body = nil
				err = errRead
			}
			parseProc(name, body, err, values)
		}
	} else {
		stats, err := c.reader.root(ctx)
		numbers := []uint64{stats.Total, stats.Free, stats.Available, stats.Inodes, stats.FreeInodes}
		if err == nil && (stats.Total == 0 || stats.Free > stats.Total || stats.Available > stats.Free || stats.FreeInodes > stats.Inodes) {
			err = errRead
		}
		for i, f := range telemetry.ProfileFields(profile) {
			v := unsigned(numbers[i])
			if err != nil {
				v = observation{reason: reason(err)}
			} else if i >= 3 && stats.Inodes == 0 {
				v = observation{reason: "MISSING"}
			}
			values[f.Metric] = v
		}
	}
	if err := ctx.Err(); err != nil {
		return telemetry.SourceFrame{}, err
	}
	completed := c.now().Round(0).UTC()
	if completed.Before(at) {
		return telemetry.SourceFrame{}, telemetry.ErrInvalid
	}
	frame := telemetry.SourceFrame{SourceID: source, SchemaVersion: 1, AdapterVersion: profile, ProfileID: profile, StartedAt: at, CompletedAt: completed}
	for i, f := range telemetry.ProfileFields(profile) {
		v, exists := values[f.Metric]
		if !exists {
			v.reason = "MISSING"
		}
		state := "UNKNOWN"
		if v.reason == "UNSUPPORTED" {
			state = "NOT_SUPPORTED"
		}
		if v.reason == "OBSERVED" {
			state = "SUPPORTED"
			frame.Records = append(frame.Records, telemetry.Record{ID: prefix + "-r" + strconv.Itoa(i), EntityKey: identity.Key(), Metric: f.Metric, Unit: f.Unit, Kind: "gauge", Reset: "not_applicable", ObservedAt: completed, CollectedAt: completed, Value: v.value})
		}
		frame.Fields = append(frame.Fields, telemetry.FieldSupport{EntityKey: identity.Key(), Metric: f.Metric, State: state, Reason: v.reason})
	}
	frame.Coverage = telemetry.Coverage{Expected: int64(len(frame.Fields)), Returned: int64(len(frame.Records)), Complete: len(frame.Fields) == len(frame.Records)}
	frame.Status = "PARTIAL"
	if frame.Coverage.Complete {
		frame.Status = "SUCCEEDED"
	} else if len(frame.Records) == 0 {
		frame.Status = "FAILED"
	}
	return frame, nil
}

func parseProc(name string, body []byte, readErr error, values map[string]observation) {
	metrics := map[string][]string{"meminfo": {"host.memory.total_bytes", "host.memory.available_bytes"}, "loadavg": {"host.load.one", "host.load.five", "host.load.fifteen"}, "uptime": {"host.uptime_seconds"}}[name]
	for _, metric := range metrics {
		values[metric] = observation{reason: "MISSING"}
	}
	if readErr != nil {
		for _, m := range metrics {
			values[m] = observation{reason: reason(readErr)}
		}
		return
	}
	if name == "meminfo" {
		seen := map[string]bool{}
		for _, line := range strings.Split(string(body), "\n") {
			parts := strings.Fields(line)
			if len(parts) == 0 {
				continue
			}
			metric := ""
			switch parts[0] {
			case "MemTotal:":
				metric = metrics[0]
			case "MemAvailable:":
				metric = metrics[1]
			default:
				continue
			}
			v := observation{reason: "SOURCE_FAILED"}
			if !seen[metric] && len(parts) == 3 && parts[2] == "kB" {
				n, err := strconv.ParseUint(parts[1], 10, 64)
				if err == nil && n <= math.MaxUint64/1024 && (metric != metrics[0] || n > 0) {
					v = unsigned(n * 1024)
				}
			}
			seen[metric] = true
			values[metric] = v
		}
		total, avail := values[metrics[0]], values[metrics[1]]
		if total.reason == "OBSERVED" && avail.reason == "OBSERVED" {
			a, _ := strconv.ParseUint(total.value.Unsigned, 10, 64)
			b, _ := strconv.ParseUint(avail.value.Unsigned, 10, 64)
			if b > a {
				values[metrics[1]] = observation{reason: "SOURCE_FAILED"}
			}
		}
		return
	}
	parts := strings.Fields(string(body))
	for i, metric := range metrics {
		if i >= len(parts) {
			continue
		}
		n, err := strconv.ParseFloat(parts[i], 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 {
			values[metric] = observation{reason: "SOURCE_FAILED"}
		} else {
			values[metric] = floating(n)
		}
	}
}
