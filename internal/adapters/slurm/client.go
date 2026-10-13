// Package slurm provides bounded, read-only Slurm CLI collection and
// deterministic normalization. JSON emitted by Slurm remains at this boundary.
package slurm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adapters/source"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	defaultMaxBytes   = 8 << 20
	defaultMaxRecords = 10_000
	maxWindow         = 7 * 24 * time.Hour
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Runner interface {
	Run(context.Context, int, string, ...string) ([]byte, error)
}

type execRunner struct{ timeout time.Duration }

var errOutputLimit = errors.New("slurm command output limit exceeded")

func (r execRunner) Run(ctx context.Context, maxBytes int, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	if name == "sacct" {
		// Slurm 23.02 rejects RFC3339's Z suffix. Keep its zone-less CLI
		// arguments unambiguously UTC without changing the collector process.
		command.Env = append(os.Environ(), "TZ=UTC")
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(stdout, int64(maxBytes)+1))
	if len(body) > maxBytes {
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, errOutputLimit
	}
	waitErr := command.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if readErr != nil {
		return nil, readErr
	}
	if waitErr != nil {
		return nil, waitErr
	}
	return body, nil
}

type Config struct {
	Timeout                     time.Duration
	MaxBytes                    int
	MaxRecords                  int
	Runner                      Runner
	SupportedDataParserVersions []string
}

type Client struct {
	runner                      Runner
	maxBytes                    int
	maxRecords                  int
	supportedDataParserVersions map[string]struct{}
}

type SchemaSupport string

const (
	SchemaSupportUnknown     SchemaSupport = "UNKNOWN"
	SchemaSupportSupported   SchemaSupport = "SUPPORTED"
	SchemaSupportUnsupported SchemaSupport = "UNSUPPORTED"
)

type FieldQuality string

const (
	FieldPresent     FieldQuality = "PRESENT"
	FieldMissing     FieldQuality = "MISSING"
	FieldUnsupported FieldQuality = "UNSUPPORTED"
	FieldUnset       FieldQuality = "UNSET"
	FieldInfinite    FieldQuality = "INFINITE"
	FieldMalformed   FieldQuality = "MALFORMED"
)

type FieldObservation struct {
	Name    string
	Quality FieldQuality
}

type Record struct {
	Kind string
	ID   string
	// State retains every Slurm state token, including coexisting flags.
	State string
	// ObservedAt is a legacy lifecycle timestamp, not Sherlock receipt time.
	ObservedAt time.Time
	Attributes []domain.Label
	Fields     []FieldObservation
}

type Result struct {
	Records           []Record
	BytesRead         int
	DataParserVersion string
	SlurmVersion      string
	SchemaSupport     SchemaSupport
	ReportedErrors    int
	ReportedWarnings  int
}

func NewClient(cfg Config) (*Client, error) {
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("slurm timeout must be positive")
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = defaultMaxBytes
	}
	if cfg.MaxRecords == 0 {
		cfg.MaxRecords = defaultMaxRecords
	}
	if cfg.MaxBytes < 1 || cfg.MaxBytes > defaultMaxBytes || cfg.MaxRecords < 1 || cfg.MaxRecords > defaultMaxRecords {
		return nil, fmt.Errorf("slurm response limits are invalid")
	}
	if cfg.Runner == nil {
		cfg.Runner = execRunner{timeout: cfg.Timeout}
	}
	supported := make(map[string]struct{}, len(cfg.SupportedDataParserVersions))
	for _, version := range cfg.SupportedDataParserVersions {
		if len(version) == 0 || len(version) > 128 || strings.TrimSpace(version) != version || strings.ContainsAny(version, "\x00\r\n\t") {
			return nil, fmt.Errorf("slurm data parser version allowlist is invalid")
		}
		supported[version] = struct{}{}
	}
	return &Client{runner: cfg.Runner, maxBytes: cfg.MaxBytes, maxRecords: cfg.MaxRecords, supportedDataParserVersions: supported}, nil
}

func (c *Client) DiscoverCapabilities(ctx context.Context) ([]source.Capability, error) {
	body, err := c.run(ctx, "sinfo", "--version")
	if err != nil {
		return nil, err
	}
	version := strings.TrimSpace(string(body))
	return []source.Capability{{ID: "slurm.inventory.v1", Version: version}, {ID: "slurm.accounting.v1", Version: version}}, nil
}

func (c *Client) Health(ctx context.Context) (source.Health, error) {
	caps, err := c.DiscoverCapabilities(ctx)
	if err != nil {
		return source.Health{}, err
	}
	return source.Health{Reachable: true, Capabilities: caps}, nil
}

func (c *Client) Inventory(ctx context.Context) (Result, error) {
	return c.query(ctx, "cluster", "sinfo", "--json")
}
func (c *Client) Nodes(ctx context.Context, names []string) (Result, error) {
	args := []string{"show", "nodes", "--json"}
	if err := validateIDs(names, 1024); err != nil {
		return Result{}, source.InvalidArgument("invalid Slurm node scope")
	}
	if len(names) > 0 {
		args = append(args, strings.Join(names, ","))
	}
	return c.query(ctx, "node", "scontrol", args...)
}
func (c *Client) Partitions(ctx context.Context, names []string) (Result, error) {
	args := []string{"show", "partitions", "--json"}
	if err := validateIDs(names, 256); err != nil {
		return Result{}, source.InvalidArgument("invalid Slurm partition scope")
	}
	if len(names) > 0 {
		args = append(args, strings.Join(names, ","))
	}
	return c.query(ctx, "partition", "scontrol", args...)
}
func (c *Client) Jobs(ctx context.Context, jobIDs []string) (Result, error) {
	args := []string{"--json"}
	if err := validateIDs(jobIDs, 1024); err != nil {
		return Result{}, source.InvalidArgument("invalid Slurm job scope")
	}
	if len(jobIDs) > 0 {
		args = append(args, "--jobs="+strings.Join(jobIDs, ","))
	}
	return c.query(ctx, "job", "squeue", args...)
}
func (c *Client) Accounting(ctx context.Context, start, end time.Time, jobIDs []string) (Result, error) {
	return c.accounting(ctx, start, end, "", jobIDs, false)
}

// AccountingAllocations requests allocation rows including duplicate/reused
// job IDs from one exact Slurm cluster. It remains unwired until GP-05b adds
// reviewed runtime visibility and persistence authority.
func (c *Client) AccountingAllocations(ctx context.Context, start, end time.Time, cluster string, jobIDs []string) (Result, error) {
	if !identifierPattern.MatchString(cluster) {
		return Result{}, source.InvalidArgument("invalid Slurm accounting cluster")
	}
	return c.accounting(ctx, start, end, cluster, jobIDs, true)
}

func (c *Client) accounting(ctx context.Context, start, end time.Time, cluster string, jobIDs []string, allocationsOnly bool) (Result, error) {
	if start.IsZero() || end.IsZero() || !end.After(start) || end.Sub(start) > maxWindow {
		return Result{}, source.InvalidArgument("invalid Slurm accounting window")
	}
	if err := validateIDs(jobIDs, 1024); err != nil {
		return Result{}, source.InvalidArgument("invalid Slurm accounting job scope")
	}
	const slurmCLITime = "2006-01-02T15:04:05"
	args := []string{"--json", "--starttime=" + start.UTC().Format(slurmCLITime), "--endtime=" + end.UTC().Format(slurmCLITime)}
	if allocationsOnly {
		args = append(args, "--allocations", "--duplicates", "--clusters="+cluster)
	}
	if len(jobIDs) > 0 {
		args = append(args, "--jobs="+strings.Join(jobIDs, ","))
	}
	return c.query(ctx, "accounting_job", "sacct", args...)
}

func validateIDs(values []string, maximum int) error {
	if len(values) > maximum {
		return fmt.Errorf("too many identifiers")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("invalid identifier")
		}
		if _, ok := seen[value]; ok {
			return fmt.Errorf("duplicate identifier")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func (c *Client) query(ctx context.Context, kind, command string, args ...string) (Result, error) {
	body, err := c.run(ctx, command, args...)
	if err != nil {
		return Result{}, err
	}
	records, metadata, err := normalize(kind, body, c.maxRecords)
	if err != nil {
		return Result{}, err
	}
	support := SchemaSupportUnknown
	if metadata.DataParserVersion != "" && len(c.supportedDataParserVersions) > 0 {
		if _, ok := c.supportedDataParserVersions[metadata.DataParserVersion]; ok {
			support = SchemaSupportSupported
		} else {
			support = SchemaSupportUnsupported
		}
	}
	return Result{Records: records, BytesRead: len(body), DataParserVersion: metadata.DataParserVersion, SlurmVersion: metadata.SlurmVersion, SchemaSupport: support, ReportedErrors: metadata.ReportedErrors, ReportedWarnings: metadata.ReportedWarnings}, nil
}

func (c *Client) run(ctx context.Context, command string, args ...string) ([]byte, error) {
	body, err := c.runner.Run(ctx, c.maxBytes, command, args...)
	if err != nil {
		if errors.Is(err, errOutputLimit) {
			return nil, source.NewError(domain.FailureResultLimit, false, "Slurm response exceeds byte limit", nil)
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, source.NewError(domain.FailureDeadlineExceeded, true, "Slurm query timed out", err)
		}
		return nil, source.NewError(domain.FailureSourceUnavailable, true, "Slurm source unavailable", err)
	}
	if len(body) > c.maxBytes {
		return nil, source.NewError(domain.FailureResultLimit, false, "Slurm response exceeds byte limit", nil)
	}
	return body, nil
}

type outputMetadata struct {
	DataParserVersion string
	SlurmVersion      string
	ReportedErrors    int
	ReportedWarnings  int
}

func normalize(kind string, body []byte, maximum int) ([]Record, outputMetadata, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		return nil, outputMetadata{}, malformed(err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, outputMetadata{}, malformed(fmt.Errorf("trailing JSON"))
	}
	metadata, err := parseOutputMetadata(root)
	if err != nil {
		return nil, outputMetadata{}, malformed(err)
	}
	var rows []any
	for _, key := range keysFor(kind) {
		if candidate, ok := root[key].([]any); ok {
			rows = candidate
			break
		}
	}
	if rows == nil {
		return nil, metadata, malformed(fmt.Errorf("missing records"))
	}
	if len(rows) > maximum {
		return nil, metadata, source.NewError(domain.FailureResultLimit, false, "Slurm record limit exceeded", nil)
	}
	result := make([]Record, 0, len(rows))
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return nil, metadata, malformed(fmt.Errorf("record is not an object"))
		}
		id := firstString(row, idKeys(kind)...)
		if id == "" {
			return nil, metadata, malformed(fmt.Errorf("record identity missing"))
		}
		state := firstJoinedPath(row, "+", "state/current", "state", "job_state", "partition/state", "partition_state")
		observed := firstTimePath(row, "last_busy", "time/submission", "submit_time", "time/start", "start_time", "time")
		attrs := extractAttributes(kind, row, metadata.DataParserVersion)
		result = append(result, Record{Kind: kind, ID: id, State: state, ObservedAt: observed, Attributes: domain.SortedLabels(attrs), Fields: observeFields(kind, row, metadata.DataParserVersion)})
	}
	return result, metadata, nil
}

func parseOutputMetadata(root map[string]any) (outputMetadata, error) {
	meta, _ := root["meta"].(map[string]any)
	plugin, _ := meta["plugin"].(map[string]any)
	if plugin == nil {
		plugin, _ = meta["plugins"].(map[string]any)
	}
	result := outputMetadata{DataParserVersion: firstString(plugin, "data_parser")}
	slurm, _ := meta["Slurm"].(map[string]any)
	if slurm == nil {
		slurm, _ = meta["slurm"].(map[string]any)
	}
	if version, ok := slurm["version"].(map[string]any); ok {
		major, minor, micro := firstString(version, "major"), firstString(version, "minor"), firstString(version, "micro")
		if major != "" && minor != "" && micro != "" {
			result.SlurmVersion = strings.Join([]string{major, minor, micro}, ".")
		}
	} else {
		result.SlurmVersion = firstString(slurm, "version")
	}
	var err error
	if result.ReportedErrors, err = diagnosticCount(root, "errors"); err != nil {
		return outputMetadata{}, err
	}
	if result.ReportedWarnings, err = diagnosticCount(root, "warnings"); err != nil {
		return outputMetadata{}, err
	}
	return result, nil
}

func diagnosticCount(root map[string]any, key string) (int, error) {
	value, exists := root[key]
	if !exists || value == nil {
		return 0, nil
	}
	items, ok := value.([]any)
	if !ok {
		return 0, fmt.Errorf("%s must be an array or null", key)
	}
	return len(items), nil
}

func observeFields(kind string, row map[string]any, dataParserVersion string) []FieldObservation {
	names := []string{"state"}
	switch kind {
	case "node":
		names = []string{"name", "state"}
	case "partition":
		return []FieldObservation{
			observeField(row, "name", "name"), observeField(row, "state", "partition/state", "state"), observeField(row, "nodes", "nodes/configured", "nodes"),
		}
	case "job":
		return []FieldObservation{
			observeField(row, "job_id", "job_id"), observeField(row, "job_state", "job_state", "state"), observeTimestampField(row, "submit_time", dataParserVersion, "submit_time"), observeTimestampField(row, "start_time", dataParserVersion, "start_time"), observeTimestampField(row, "end_time", dataParserVersion, "end_time"), observeField(row, "restart_cnt", "restart_cnt"), observeField(row, "nodes", "nodes"), observeField(row, "cluster", "cluster"),
		}
	case "accounting_job":
		fields := []FieldObservation{
			observeField(row, "job_id", "job_id"), observeField(row, "job_state", "state/current"), observeAccountingTimeField(row, "submit_time", dataParserVersion, "time/submission"), observeAccountingTimeField(row, "start_time", dataParserVersion, "time/start"), observeAccountingTimeField(row, "end_time", dataParserVersion, "time/end"), observeField(row, "restart_cnt", "restart_cnt"), observeField(row, "nodes", "nodes"), observeField(row, "cluster", "cluster"),
		}
		if dataParserVersion == "data_parser/v0.0.40" && fields[5].Quality == FieldMissing {
			fields[5].Quality = FieldUnsupported
		}
		return fields
	}
	observations := make([]FieldObservation, 0, len(names))
	for _, name := range names {
		quality := FieldMissing
		if value, exists := row[name]; exists {
			quality = classifyField(value)
		}
		observations = append(observations, FieldObservation{Name: name, Quality: quality})
	}
	return observations
}

func observeTimestampField(row map[string]any, canonical, dataParserVersion string, paths ...string) FieldObservation {
	if dataParserVersion == domain.SlurmSnapshotDataParserVersion2302 {
		for _, path := range paths {
			value, exists := lookupPath(row, path)
			if !exists {
				continue
			}
			if scalar, ok := scalarString(value); ok && scalar == "0" || canonical == "end_time" && path == "end_time" && v39ProjectedEndTime(row) {
				return FieldObservation{Name: canonical, Quality: FieldUnset}
			}
			return FieldObservation{Name: canonical, Quality: classifyField(value)}
		}
		return FieldObservation{Name: canonical, Quality: FieldMissing}
	}
	if dataParserVersion != "data_parser/v0.0.40" {
		return observeField(row, canonical, paths...)
	}
	for _, path := range paths {
		value, exists := lookupPath(row, path)
		if !exists {
			continue
		}
		_, quality, _ := noValueWrapper(value)
		return FieldObservation{Name: canonical, Quality: quality}
	}
	return FieldObservation{Name: canonical, Quality: FieldMissing}
}

func observeAccountingTimeField(row map[string]any, canonical, dataParserVersion, path string) FieldObservation {
	if dataParserVersion == domain.SlurmSnapshotDataParserVersion2302 {
		return observeTimestampField(row, canonical, dataParserVersion, path)
	}
	return observeField(row, canonical, path)
}

func observeField(row map[string]any, canonical string, paths ...string) FieldObservation {
	quality := FieldMissing
	for _, path := range paths {
		value, exists := lookupPath(row, path)
		if !exists {
			continue
		}
		candidate := classifyField(value)
		if candidate == FieldPresent {
			quality = candidate
			break
		}
		if candidate != FieldMissing {
			quality = candidate
		}
	}
	return FieldObservation{Name: canonical, Quality: quality}
}

func extractAttributes(kind string, row map[string]any, dataParserVersion string) map[string]string {
	attributes := make(map[string]string)
	for key, value := range row {
		if kind == "job" && dataParserVersion == domain.SlurmSnapshotDataParserVersion2302 && key == "end_time" && v39ProjectedEndTime(row) {
			continue
		}
		if dataParserVersion == "data_parser/v0.0.40" && (key == "submit_time" || key == "start_time" || key == "end_time") {
			if scalar, quality, _ := noValueWrapper(value); quality == FieldPresent {
				attributes[key] = scalar
			}
			continue
		}
		if scalar, ok := joinedString(value, ","); ok {
			attributes[key] = scalar
		}
	}
	reviewed := map[string][]string{
		"partition":      {"nodes/configured", "partition/state"},
		"accounting_job": {"state/current", "time/submission", "time/start", "time/end"},
	}
	for _, path := range reviewed[kind] {
		value, exists := lookupPath(row, path)
		if !exists {
			continue
		}
		if scalar, ok := joinedString(value, ","); ok {
			attributes[path] = scalar
		}
	}
	return attributes
}

// The 23.02 squeue end_time of an active job is its scheduled limit, not an
// observed completion. Treat it as unset rather than recording a future fact.
func v39ProjectedEndTime(row map[string]any) bool {
	state := firstJoinedPath(row, "+", "job_state", "state")
	return state == "RUNNING" || state == "PENDING" || state == "SUSPENDED" || state == "CONFIGURING"
}

func noValueWrapper(value any) (string, FieldQuality, bool) {
	object, ok := value.(map[string]any)
	if !ok {
		return "", FieldMalformed, false
	}
	set, setOK := object["set"].(bool)
	infinite, infiniteOK := object["infinite"].(bool)
	number, numberOK := scalarString(object["number"])
	if !setOK || !infiniteOK || !numberOK || len(object) != 3 {
		return "", FieldMalformed, true
	}
	parsed, err := strconv.ParseUint(number, 10, 64)
	if err != nil {
		return "", FieldMalformed, true
	}
	if infinite {
		if set || parsed != 0 {
			return "", FieldMalformed, true
		}
		return "", FieldInfinite, true
	}
	if !set {
		if parsed != 0 {
			return "", FieldMalformed, true
		}
		return "", FieldUnset, true
	}
	return strconv.FormatUint(parsed, 10), FieldPresent, true
}

func lookupPath(row map[string]any, path string) (any, bool) {
	var current any = row
	for _, part := range strings.Split(path, "/") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func classifyField(value any) FieldQuality {
	if value == nil {
		return FieldMissing
	}
	if object, ok := value.(map[string]any); ok {
		if set, exists := object["set"].(bool); exists && !set {
			return FieldUnsupported
		}
		return FieldMalformed
	}
	if text, ok := joinedString(value, ","); ok && text != "" {
		return FieldPresent
	}
	return FieldMalformed
}

func keysFor(kind string) []string {
	switch kind {
	case "node":
		return []string{"nodes"}
	case "partition":
		return []string{"partitions"}
	case "job", "accounting_job":
		return []string{"jobs"}
	default:
		return []string{"nodes", "partitions"}
	}
}
func idKeys(kind string) []string {
	switch kind {
	case "node":
		return []string{"name", "node_name"}
	case "partition":
		return []string{"name", "partition_name"}
	case "job", "accounting_job":
		return []string{"job_id", "job_id_raw", "id"}
	default:
		return []string{"name", "cluster"}
	}
}
func firstString(row map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := scalarString(row[key]); ok {
			return value
		}
	}
	return ""
}

func firstJoinedPath(row map[string]any, separator string, paths ...string) string {
	for _, path := range paths {
		value, exists := lookupPath(row, path)
		if !exists {
			continue
		}
		if joined, ok := joinedString(value, separator); ok {
			return joined
		}
	}
	return ""
}

func joinedString(value any, separator string) (string, bool) {
	if scalar, ok := scalarString(value); ok {
		return scalar, true
	}
	values, ok := value.([]any)
	if !ok || len(values) == 0 {
		return "", false
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		scalar, ok := scalarString(value)
		if !ok {
			return "", false
		}
		parts = append(parts, scalar)
	}
	return strings.Join(parts, separator), true
}

func scalarString(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, v != ""
	case json.Number:
		return v.String(), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(v), true
	default:
		return "", false
	}
}
func firstTimePath(row map[string]any, paths ...string) time.Time {
	for _, path := range paths {
		value, exists := lookupPath(row, path)
		if !exists {
			continue
		}
		text, ok := scalarString(value)
		if !ok {
			var quality FieldQuality
			text, quality, _ = noValueWrapper(value)
			if quality != FieldPresent {
				continue
			}
		}
		if seconds, err := strconv.ParseInt(text, 10, 64); err == nil && seconds > 0 {
			return time.Unix(seconds, 0).UTC()
		}
		if parsed, err := time.Parse(time.RFC3339, text); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}
func malformed(err error) error {
	return source.NewError(domain.FailureMalformedResponse, false, "Slurm returned a malformed response", err)
}
