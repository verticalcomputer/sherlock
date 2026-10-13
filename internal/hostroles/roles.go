// Package hostroles derives which hosts hold which diagnostic target role from
// systems that already know: Slurm, collector coverage, and Redfish.
//
// A host-role map decides which machines are reached and what runs on them.
// That is a targeting decision, so it is deterministic code over observations
// this repository already collects, and never model output. Nothing in this
// package accepts free text from a planner, and its inputs are typed
// observations produced by adapters.
//
// Every entry records why it holds its role and when that was last confirmed,
// and entries expire: a node Slurm has not recently confirmed must not receive
// a diagnostic, and an operator should not have to remove it by hand.
package hostroles

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type Source string

const (
	// SourceSlurm is the cluster's own authoritative definition of a compute
	// node and of the controller host.
	SourceSlurm Source = "SLURM"
	// SourceCollectorCoverage is a target Sherlock has actually observed, which
	// confirms both that the host exists and that it is reachable.
	SourceCollectorCoverage Source = "COLLECTOR_COVERAGE"
	// SourceRedfish identifies BMC gateways.
	SourceRedfish Source = "REDFISH"
)

func (source Source) Validate() error {
	switch source {
	case SourceSlurm, SourceCollectorCoverage, SourceRedfish:
		return nil
	default:
		return fmt.Errorf("unknown host role source %q", source)
	}
}

// Entry is one derived role assignment together with its provenance.
type Entry struct {
	ClusterID   domain.ClusterID
	Target      domain.DiagnosticTarget
	Role        commandpack.TargetRole
	Sources     []Source
	Reason      string
	ConfirmedAt time.Time
}

// SlurmNode is what scontrol reports about one node.
type SlurmNode struct {
	Name       string
	State      string
	Partition  string
	Controller bool
	ObservedAt time.Time
}

// CoverageTarget is a node Sherlock has actually collected from.
type CoverageTarget struct {
	Node       string
	ObservedAt time.Time
}

// RedfishEndpoint is a BMC Sherlock has reached.
type RedfishEndpoint struct {
	Host       string
	ObservedAt time.Time
}

type Observations struct {
	ClusterID  domain.ClusterID
	SlurmNodes []SlurmNode
	Coverage   []CoverageTarget
	Redfish    []RedfishEndpoint
}

// Derive turns one cluster's observations into role entries.
//
// Sources that agree reinforce an entry and the most recent confirmation wins,
// because a role confirmed by two systems is better evidence than one. Sources
// that disagree remove the target entirely rather than picking a winner: a host
// that Slurm calls a controller and coverage calls a compute node is a host
// nobody should send a role-scoped command to until the disagreement is
// resolved. Silently preferring either answer is how a controller ends up
// running a compute diagnostic.
func Derive(observations Observations) ([]Entry, []Conflict, error) {
	if observations.ClusterID == "" {
		return nil, nil, fmt.Errorf("host role derivation requires a cluster")
	}
	type candidate struct {
		role        commandpack.TargetRole
		sources     []Source
		reasons     []string
		confirmedAt time.Time
		conflicting bool
	}
	candidates := map[domain.DiagnosticTarget]*candidate{}
	record := func(name string, role commandpack.TargetRole, source Source, reason string, observedAt time.Time) error {
		if name == "" || observedAt.IsZero() {
			return fmt.Errorf("host role observation for %q is incomplete", name)
		}
		target := domain.DiagnosticTarget(name)
		existing, seen := candidates[target]
		if !seen {
			candidates[target] = &candidate{role: role, sources: []Source{source}, reasons: []string{reason}, confirmedAt: observedAt.UTC()}
			return nil
		}
		if existing.role != role {
			existing.conflicting = true
			existing.reasons = append(existing.reasons, reason)
			if !slices.Contains(existing.sources, source) {
				existing.sources = append(existing.sources, source)
			}
			return nil
		}
		if !slices.Contains(existing.sources, source) {
			existing.sources = append(existing.sources, source)
		}
		existing.reasons = append(existing.reasons, reason)
		if observedAt.After(existing.confirmedAt) {
			existing.confirmedAt = observedAt.UTC()
		}
		return nil
	}

	for _, node := range observations.SlurmNodes {
		role, reason := commandpack.TargetCompute, fmt.Sprintf("Slurm reports node %s in partition %s with state %s", node.Name, node.Partition, node.State)
		if node.Controller {
			role, reason = commandpack.TargetHead, fmt.Sprintf("Slurm reports %s as the controller host", node.Name)
		}
		if err := record(node.Name, role, SourceSlurm, reason, node.ObservedAt); err != nil {
			return nil, nil, err
		}
	}
	for _, target := range observations.Coverage {
		if err := record(target.Node, commandpack.TargetCompute, SourceCollectorCoverage, fmt.Sprintf("collector coverage observed node %s", target.Node), target.ObservedAt); err != nil {
			return nil, nil, err
		}
	}
	for _, endpoint := range observations.Redfish {
		if err := record(endpoint.Host, commandpack.TargetBMCGateway, SourceRedfish, fmt.Sprintf("Redfish reached BMC %s", endpoint.Host), endpoint.ObservedAt); err != nil {
			return nil, nil, err
		}
	}

	entries := make([]Entry, 0, len(candidates))
	conflicts := make([]Conflict, 0)
	for target, value := range candidates {
		if value.conflicting {
			conflicts = append(conflicts, Conflict{ClusterID: observations.ClusterID, Target: target, Sources: slices.Clone(value.sources), Reason: strings.Join(value.reasons, "; ")})
			continue
		}
		slices.Sort(value.sources)
		entries = append(entries, Entry{ClusterID: observations.ClusterID, Target: target, Role: value.role, Sources: value.sources, Reason: strings.Join(value.reasons, "; "), ConfirmedAt: value.confirmedAt})
	}
	slices.SortFunc(entries, func(left, right Entry) int { return strings.Compare(string(left.Target), string(right.Target)) })
	slices.SortFunc(conflicts, func(left, right Conflict) int { return strings.Compare(string(left.Target), string(right.Target)) })
	return entries, conflicts, nil
}

// Conflict records a target whose role could not be derived unambiguously. It
// is reported rather than resolved so an operator can see why a host became
// ineligible instead of finding it silently missing.
type Conflict struct {
	ClusterID domain.ClusterID
	Target    domain.DiagnosticTarget
	Sources   []Source
	Reason    string
}

// Resolver answers role questions from derived entries, applying expiry.
type Resolver struct {
	ttl     time.Duration
	entries map[domain.ClusterID]map[domain.DiagnosticTarget]Entry
}

func NewResolver(ttl time.Duration) (*Resolver, error) {
	if ttl <= 0 || ttl > 24*time.Hour {
		return nil, fmt.Errorf("host role confirmation lifetime must be positive and within a day")
	}
	return &Resolver{ttl: ttl, entries: map[domain.ClusterID]map[domain.DiagnosticTarget]Entry{}}, nil
}

// Replace installs one cluster's derived entries, discarding whatever it held
// before. Replacement rather than merge is what makes removal automatic: a node
// Slurm no longer reports simply is not in the next derivation, so it stops
// being eligible without an operator deleting anything.
func (resolver *Resolver) Replace(clusterID domain.ClusterID, entries []Entry) error {
	if resolver == nil || clusterID == "" {
		return fmt.Errorf("host role resolver and cluster are required")
	}
	installed := make(map[domain.DiagnosticTarget]Entry, len(entries))
	for _, entry := range entries {
		if entry.ClusterID != clusterID || entry.Target == "" || entry.Reason == "" || entry.ConfirmedAt.IsZero() || len(entry.Sources) == 0 {
			return fmt.Errorf("host role entry for %q is incomplete", entry.Target)
		}
		switch entry.Role {
		case commandpack.TargetHead, commandpack.TargetCompute, commandpack.TargetBMCGateway:
		default:
			return fmt.Errorf("host role entry for %q has an unknown role", entry.Target)
		}
		for _, source := range entry.Sources {
			if err := source.Validate(); err != nil {
				return err
			}
		}
		installed[entry.Target] = Entry{ClusterID: clusterID, Target: entry.Target, Role: entry.Role, Sources: slices.Clone(entry.Sources), Reason: entry.Reason, ConfirmedAt: entry.ConfirmedAt.UTC()}
	}
	resolver.entries[clusterID] = installed
	return nil
}

// Role reports the derived role for one target, or false when the target is
// unknown or its confirmation has aged out. Both answers make the target
// ineligible for a diagnostic; neither is an error.
func (resolver *Resolver) Role(clusterID domain.ClusterID, target domain.DiagnosticTarget, now time.Time) (Entry, bool) {
	if resolver == nil {
		return Entry{}, false
	}
	entry, exists := resolver.entries[clusterID][target]
	if !exists || now.Sub(entry.ConfirmedAt) > resolver.ttl || now.Before(entry.ConfirmedAt) {
		return Entry{}, false
	}
	entry.Sources = slices.Clone(entry.Sources)
	return entry, true
}
