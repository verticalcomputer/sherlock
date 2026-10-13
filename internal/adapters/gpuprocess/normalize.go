// Package gpuprocess normalizes local evidence only. It performs no I/O and
// has no collection, scheduling, diagnostic, or repair authority.
package gpuprocess

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	Format     = "nvidia.compute_processes.v1"
	FormatV2   = "nvidia.compute_processes.v2"
	MaxBytes   = 1 << 20
	MaxRecords = 4096
	MaxAge     = time.Minute
)

type Gap string

const (
	Missing                   Gap = "MISSING"
	Stale                     Gap = "STALE"
	Truncated                 Gap = "TRUNCATED"
	Malformed                 Gap = "MALFORMED"
	PermissionDenied          Gap = "PERMISSION_DENIED"
	AuthenticationUnavailable Gap = "AUTHENTICATION_UNAVAILABLE"
	Timeout                   Gap = "TIMEOUT"
	Unsupported               Gap = "UNSUPPORTED"
	VisibilityUnknown         Gap = "VISIBILITY_UNKNOWN"
	NodeUnknown               Gap = "NODE_UNKNOWN"
	GPUUnknown                Gap = "GPU_UNKNOWN"
	MIGAmbiguous              Gap = "MIG_AMBIGUOUS"
	StartUnknown              Gap = "START_UNKNOWN"
	PIDReused                 Gap = "PID_REUSED"
	AssociationUnproven       Gap = "ASSOCIATION_UNPROVEN"
	OutputLimit               Gap = "OUTPUT_LIMIT"
)

// Config is local authority, never fields inferred from command output.
// CompleteComputeVisibility covers only NVIDIA compute-app query membership.
// PhysicalOnly requires independent knowledge that MIG is disabled on target.
// PIDNamespace must describe the NVIDIA source's PID namespace, not merely the
// namespace of the reader. Unknown Node/PIDNamespace are permitted as gaps.
type Config struct {
	ClusterID                 domain.ClusterID
	SourceID                  domain.SourceID
	Node                      *domain.EntityIdentity
	GPUs                      []domain.EntityIdentity
	PIDNamespace              string
	CompleteComputeVisibility bool
	PhysicalOnly              bool
	SchedulerNamespace        domain.SchedulerNamespace
	MembershipSourceID        domain.SourceID
}

// ProcSample is targeted evidence; no /proc traversal or command line read is
// authorized. Stat is bounded /proc/PID/stat; BootID and PIDNamespace come from
// /proc/sys/kernel/random/boot_id and the source's /proc/self/ns/pid link.
type ProcSample struct {
	Node         domain.EntityIdentity
	At           time.Time
	BootID       string
	PIDNamespace string
	Stat         string
	Failure      Gap
}

type ProcessEvidence struct {
	PID    uint32
	Before ProcSample
	After  ProcSample
}

// TaskMembership is an externally trusted scheduler task-membership receipt,
// NOT raw command output or a claim inferred from a cgroup name. Its producer
// must establish the full attempt and process incarnation for the interval.
// This packet supplies no such producer. Local config must pin its source and
// scheduler namespace. A receipt never confers scheduler allocation authority.
type TaskMembership struct {
	SourceID     domain.SourceID
	Process      domain.GPUProcessIdentity
	Job          domain.JobIdentity
	ValidFrom    time.Time
	ValidThrough time.Time
	EvidenceID   string
}

type Input struct {
	Format string
	CSV    string
	// QuerySucceeded distinguishes an empty successful response from no
	// response. Success alone never asserts complete visibility.
	QuerySucceeded bool
	StartedAt      time.Time
	FinishedAt     time.Time
	ObservedAt     time.Time
	Failure        Gap
	Processes      []ProcessEvidence
	Memberships    []TaskMembership
}

type Observation struct {
	PID               uint32
	Process           *domain.GPUProcessIdentity
	GPUUUID           domain.PhysicalGPUUUID
	GPU               *domain.EntityIdentity
	GPUInstanceID     *uint32
	ComputeInstanceID *uint32
	Membership        *TaskMembership
	Gaps              []Gap
}

// Result deliberately has no idle flag. Even complete empty compute membership
// excludes graphics/other GPU users and cannot prove node or device idleness.
type Result struct {
	ClusterID         domain.ClusterID
	SourceID          domain.SourceID
	Node              *domain.EntityIdentity
	PIDNamespace      string
	Scope             string
	Format            string
	StartedAt         time.Time
	FinishedAt        time.Time
	ObservedAt        time.Time
	ComputeVisibility domain.SourceCoverageState
	Observations      []Observation
	Gaps              []Gap
}

var uuidPattern = regexp.MustCompile(`^GPU-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var safeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var namespacePattern = regexp.MustCompile(`^pid:\[[1-9][0-9]{0,19}\]$`)

func Normalize(cfg Config, input Input) (Result, error) {
	if err := validateConfig(cfg); err != nil {
		return Result{}, err
	}
	result := Result{ClusterID: cfg.ClusterID, SourceID: cfg.SourceID, Format: input.Format,
		PIDNamespace: cfg.PIDNamespace, Scope: "NVIDIA_COMPUTE_APPS",
		StartedAt: input.StartedAt, FinishedAt: input.FinishedAt, ObservedAt: input.ObservedAt,
		ComputeVisibility: domain.SourceCoverageUnknown}
	if cfg.Node != nil {
		node := *cfg.Node
		result.Node = &node
	}
	if input.StartedAt.IsZero() || input.FinishedAt.Before(input.StartedAt) || input.ObservedAt.Before(input.FinishedAt) || input.FinishedAt.Sub(input.StartedAt) > 15*time.Second {
		return Result{}, fmt.Errorf("invalid GPU process observation interval")
	}
	if oversized(input) {
		result.Gaps = []Gap{OutputLimit}
		return result, nil
	}
	if input.Format != Format && input.Format != FormatV2 {
		result.Gaps = []Gap{Unsupported}
		result.ComputeVisibility = domain.SourceCoverageUnsupported
		return result, nil
	}
	if input.Failure != "" {
		if !sourceFailure(input.Failure) {
			return Result{}, fmt.Errorf("invalid GPU process source failure")
		}
		result.Gaps = []Gap{input.Failure}
		result.ComputeVisibility = domain.SourceCoverageUnavailable
		return result, nil
	}
	if !input.QuerySucceeded {
		result.Gaps = []Gap{Missing}
		result.ComputeVisibility = domain.SourceCoverageUnavailable
		return result, nil
	}
	if input.ObservedAt.Sub(input.StartedAt) > MaxAge {
		result.Gaps = append(result.Gaps, Stale)
	}
	if cfg.Node == nil {
		result.Gaps = append(result.Gaps, NodeUnknown)
	}
	if len(cfg.GPUs) == 0 {
		result.Gaps = append(result.Gaps, GPUUnknown)
	}
	if cfg.PIDNamespace == "" {
		result.Gaps = append(result.Gaps, StartUnknown)
	}
	if !cfg.PhysicalOnly {
		result.Gaps = append(result.Gaps, MIGAmbiguous)
	}
	if !cfg.CompleteComputeVisibility {
		result.Gaps = append(result.Gaps, VisibilityUnknown)
	}
	processes, err := indexProcesses(cfg, input.Processes)
	if err != nil {
		return Result{}, err
	}
	input.Memberships, err = normalizeMemberships(cfg, input.Memberships)
	if err != nil {
		return Result{}, err
	}
	reader := csv.NewReader(strings.NewReader(input.CSV))
	reader.FieldsPerRecord = 4
	if input.Format == FormatV2 {
		reader.FieldsPerRecord = 2
	}
	reader.TrimLeadingSpace = true
	seenRows := map[string]bool{}
	for {
		fields, err := reader.Read()
		if err == io.EOF {
			break
		}
		if len(result.Observations) == MaxRecords {
			result.Gaps = appendUnique(result.Gaps, OutputLimit)
			break
		}
		if err != nil {
			result.Gaps = appendUnique(result.Gaps, Malformed)
			break
		}
		observation := parseRow(cfg, input.Format, fields)
		rowKey := strings.Join(fields, ",")
		if seenRows[rowKey] {
			observation.Gaps = appendUnique(observation.Gaps, Malformed)
		}
		seenRows[rowKey] = true
		if evidence, ok := processes[observation.PID]; ok {
			observation.Process, err = processIdentity(cfg, input, evidence)
			if err != nil {
				observation.Gaps = appendUnique(observation.Gaps, Gap(err.Error()))
			}
		}
		if observation.Process == nil {
			observation.Gaps = appendUnique(observation.Gaps, StartUnknown)
		}
		attachMembership(&observation, input)
		result.Observations = append(result.Observations, observation)
		for _, gap := range observation.Gaps {
			result.Gaps = appendUnique(result.Gaps, gap)
		}
	}
	if len(result.Gaps) == 0 {
		result.ComputeVisibility = domain.SourceCoverageComplete
	} else if len(result.Observations) > 0 {
		result.ComputeVisibility = domain.SourceCoveragePartial
	}
	// Expanding compact source fields into identities/receipts can exceed the
	// raw byte budget. Enforce the same bound on retained normalized evidence.
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > MaxBytes {
		result.Observations = nil
		result.ComputeVisibility = domain.SourceCoverageUnknown
		result.Gaps = appendUnique(result.Gaps, OutputLimit)
	}
	return result, nil
}

func validateConfig(cfg Config) error {
	if !safeIDPattern.MatchString(string(cfg.ClusterID)) || !safeIDPattern.MatchString(string(cfg.SourceID)) || len(cfg.GPUs) > MaxRecords {
		return fmt.Errorf("invalid GPU process local scope")
	}
	if cfg.PIDNamespace != "" && !namespacePattern.MatchString(cfg.PIDNamespace) {
		return fmt.Errorf("invalid GPU process source PID namespace")
	}
	if cfg.Node != nil {
		node, err := domain.CreateEntityIdentity(*cfg.Node)
		if err != nil || node.Kind != domain.EntityNode || node.ClusterID != cfg.ClusterID {
			return fmt.Errorf("invalid GPU process local node")
		}
	}
	seen := map[domain.PhysicalGPUUUID]bool{}
	for _, gpu := range cfg.GPUs {
		_, err := domain.CreateEntityIdentity(gpu)
		if err != nil || cfg.Node == nil || gpu.Kind != domain.EntityGPU || gpu.ClusterID != cfg.ClusterID || gpu.NodeID != cfg.Node.NodeID || !uuidPattern.MatchString(string(gpu.PhysicalGPUUUID)) || seen[gpu.PhysicalGPUUUID] {
			return fmt.Errorf("invalid GPU process local GPU mapping")
		}
		seen[gpu.PhysicalGPUUUID] = true
	}
	if (cfg.MembershipSourceID == "") != (cfg.SchedulerNamespace == "") || cfg.MembershipSourceID != "" && (!safeIDPattern.MatchString(string(cfg.MembershipSourceID)) || !safeIDPattern.MatchString(string(cfg.SchedulerNamespace))) {
		return fmt.Errorf("invalid GPU process membership source")
	}
	return nil
}

func oversized(input Input) bool {
	if len(input.Processes) > MaxRecords || len(input.Memberships) > MaxRecords || len(input.Format) > 128 {
		return true
	}
	size := len(input.CSV)
	for _, process := range input.Processes {
		for _, sample := range []ProcSample{process.Before, process.After} {
			if len(sample.Stat) > 4096 || len(sample.BootID) > 36 || len(sample.PIDNamespace) > 32 {
				return true
			}
			size += len(sample.Stat) + len(sample.BootID) + len(sample.PIDNamespace) + len(sample.Node.ClusterID) + len(sample.Node.NodeID)
		}
	}
	for _, membership := range input.Memberships {
		size += len(membership.EvidenceID) + len(membership.SourceID) + len(membership.Job.JobID) + len(membership.Job.SchedulerNamespace) + len(membership.Process.BootID) + len(membership.Process.PIDNamespace) + len(membership.Process.Node.ClusterID) + len(membership.Process.Node.NodeID)
	}
	return size > MaxBytes
}

func sourceFailure(gap Gap) bool {
	return gap == Missing || gap == Truncated || gap == Malformed || gap == PermissionDenied || gap == AuthenticationUnavailable || gap == Unsupported || gap == Timeout
}

func indexProcesses(cfg Config, evidence []ProcessEvidence) (map[uint32]ProcessEvidence, error) {
	indexed := make(map[uint32]ProcessEvidence, len(evidence))
	for _, process := range evidence {
		if process.PID == 0 || process.PID > 2147483647 {
			return nil, fmt.Errorf("invalid proc evidence PID")
		}
		if _, duplicate := indexed[process.PID]; duplicate {
			return nil, fmt.Errorf("duplicate proc evidence PID")
		}
		for _, sample := range []ProcSample{process.Before, process.After} {
			if sample.Failure != "" && !sourceFailure(sample.Failure) {
				return nil, fmt.Errorf("invalid proc source failure")
			}
			if cfg.Node == nil || sample.Node != *cfg.Node {
				return nil, fmt.Errorf("foreign proc evidence node")
			}
		}
		indexed[process.PID] = process
	}
	return indexed, nil
}

func parseRow(cfg Config, format string, fields []string) Observation {
	var observation Observation
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	pid, err := strconv.ParseUint(fields[1], 10, 31)
	if err != nil || pid == 0 {
		observation.Gaps = append(observation.Gaps, Malformed)
	} else {
		observation.PID = uint32(pid)
	}
	if uuidPattern.MatchString(fields[0]) {
		observation.GPUUUID = domain.PhysicalGPUUUID(fields[0])
		for _, gpu := range cfg.GPUs {
			if gpu.PhysicalGPUUUID == observation.GPUUUID {
				copy := gpu
				observation.GPU = &copy
				break
			}
		}
	}
	if observation.GPU == nil {
		observation.Gaps = append(observation.Gaps, GPUUnknown)
	}
	if format == FormatV2 {
		// The pilot driver rejects MIG instance fields in --query-compute-apps.
		// V2 asks only for UUID and PID; separate physical-only evidence is
		// required before treating an instance as unambiguous.
		if !cfg.PhysicalOnly {
			observation.Gaps = append(observation.Gaps, MIGAmbiguous)
		}
	} else {
		var validGI, validCI bool
		observation.GPUInstanceID, validGI = instanceID(fields[2])
		observation.ComputeInstanceID, validCI = instanceID(fields[3])
		if !validGI || !validCI {
			observation.Gaps = appendUnique(observation.Gaps, Unsupported)
		}
		if !cfg.PhysicalOnly || observation.GPUInstanceID != nil || observation.ComputeInstanceID != nil || !validGI || !validCI {
			observation.Gaps = append(observation.Gaps, MIGAmbiguous)
		}
	}
	return observation
}

func instanceID(value string) (*uint32, bool) {
	if value == "N/A" {
		return nil, true
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return nil, false
	}
	number := uint32(parsed)
	return &number, true
}

func processIdentity(cfg Config, input Input, evidence ProcessEvidence) (*domain.GPUProcessIdentity, error) {
	before, after := evidence.Before, evidence.After
	for _, sample := range []ProcSample{before, after} {
		if sample.Failure != "" {
			return nil, fmt.Errorf("%s", sample.Failure)
		}
	}
	if cfg.Node == nil || cfg.PIDNamespace == "" || before.PIDNamespace != cfg.PIDNamespace || after.PIDNamespace != cfg.PIDNamespace || before.At.IsZero() || before.At.After(input.StartedAt) || after.At.Before(input.FinishedAt) || input.StartedAt.Sub(before.At) > 15*time.Second || after.At.Sub(input.FinishedAt) > 15*time.Second || after.At.After(input.ObservedAt) {
		return nil, fmt.Errorf("%s", StartUnknown)
	}
	startBefore, okBefore := startTicks(before.Stat, evidence.PID)
	startAfter, okAfter := startTicks(after.Stat, evidence.PID)
	if !okBefore || !okAfter {
		return nil, fmt.Errorf("%s", Malformed)
	}
	if before.BootID != after.BootID || startBefore != startAfter {
		return nil, fmt.Errorf("%s", PIDReused)
	}
	identity, err := domain.CreateGPUProcessIdentity(domain.GPUProcessIdentity{Node: *cfg.Node, BootID: before.BootID, PIDNamespace: before.PIDNamespace, PID: evidence.PID, StartTicks: startBefore})
	if err != nil {
		return nil, fmt.Errorf("%s", StartUnknown)
	}
	return &identity, nil
}

func startTicks(stat string, pid uint32) (uint64, bool) {
	open, close := strings.Index(stat, " ("), strings.LastIndex(stat, ") ")
	if open < 1 || close <= open {
		return 0, false
	}
	parsedPID, err := strconv.ParseUint(stat[:open], 10, 31)
	if err != nil || uint32(parsedPID) != pid {
		return 0, false
	}
	fields := strings.Fields(stat[close+2:])
	// The fixture contract pins the modern Linux 52-field stat layout. The
	// parenthesized comm field may contain spaces and closing parentheses.
	if len(fields) != 50 || len(fields[0]) != 1 || !strings.Contains("RSDZTtXxKWPI", fields[0]) {
		return 0, false
	}
	for _, field := range fields[1:] {
		if _, signedErr := strconv.ParseInt(field, 10, 64); signedErr != nil {
			if _, unsignedErr := strconv.ParseUint(field, 10, 64); unsignedErr != nil {
				return 0, false
			}
		}
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	return ticks, err == nil && ticks != 0
}

func normalizeMemberships(cfg Config, memberships []TaskMembership) ([]TaskMembership, error) {
	normalized := make([]TaskMembership, 0, len(memberships))
	for _, membership := range memberships {
		process, processErr := domain.CreateGPUProcessIdentity(membership.Process)
		job, jobErr := domain.CreateJobIdentity(membership.Job)
		if cfg.Node == nil || processErr != nil || jobErr != nil || membership.Process.Node != *cfg.Node || cfg.MembershipSourceID == "" || membership.SourceID != cfg.MembershipSourceID || membership.Job.SchedulerNamespace != cfg.SchedulerNamespace || !safeIDPattern.MatchString(membership.EvidenceID) || !safeIDPattern.MatchString(string(membership.Job.JobID)) || membership.ValidFrom.IsZero() || membership.ValidThrough.Before(membership.ValidFrom) || membership.ValidThrough.Sub(membership.ValidFrom) > MaxAge || membership.Job.SubmitAt.After(membership.ValidFrom) {
			return nil, fmt.Errorf("invalid or foreign task membership evidence")
		}
		// Keep the constructors' canonical identities without changing the
		// caller's receipt slice. In particular, job submit time is UTC.
		membership.Process, membership.Job = process, job
		normalized = append(normalized, membership)
	}
	return normalized, nil
}

func attachMembership(observation *Observation, input Input) {
	for _, membership := range input.Memberships {
		if membership.Process.PID != observation.PID {
			continue
		}
		if observation.Process == nil || membership.Process != *observation.Process || membership.ValidFrom.After(input.StartedAt) || membership.ValidThrough.Before(input.FinishedAt) || membership.ValidThrough.After(input.ObservedAt) {
			observation.Gaps = appendUnique(observation.Gaps, AssociationUnproven)
			continue
		}
		if observation.Membership != nil {
			observation.Membership = nil
			observation.Gaps = appendUnique(observation.Gaps, AssociationUnproven)
			return
		}
		copy := membership
		observation.Membership = &copy
	}
}

func appendUnique(gaps []Gap, gap Gap) []Gap {
	for _, existing := range gaps {
		if existing == gap {
			return gaps
		}
	}
	return append(gaps, gap)
}
