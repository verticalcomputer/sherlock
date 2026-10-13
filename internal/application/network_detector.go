package application

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// NetworkPortKey is a reviewed local InfiniBand port identity. Device numbers
// do not imply a physical rail or switch mapping.
type NetworkPortKey struct {
	Node   string
	Device string
	Port   uint16
}

type NetworkPortReading struct {
	Key           NetworkPortKey
	NodeGUID      string
	LinkLayer     string
	State         string
	PhysicalState string
	LinkDowned    *uint64
}

// NetworkNodePoll is one bounded head-to-node read. Only COMPLETE permits a
// missing expected port to be interpreted as a missing port; all other outcomes
// mean the monitoring path is blind, not that a rail is down.
type NetworkNodePoll struct {
	InventoryRevision string
	Node              string
	BootID            string
	ObservedAt        time.Time
	Outcome           string
	// ReadError is a closed safe code, never raw stderr or a credential.
	ReadError          string
	Ports              []NetworkPortReading
	ManagementRevision string
	Bonds              []NetworkBondReading
}

const (
	NetworkPollComplete        = "COMPLETE"
	NetworkPollAuthUnavailable = "AUTH_UNAVAILABLE"
	NetworkPollNodeUnreachable = "NODE_UNREACHABLE"
	NetworkPollReadFailed      = "READ_FAILED"

	NetworkReadSSHAuthDenied   = "SSH_AUTH_DENIED"
	NetworkReadSSHTimeout      = "SSH_TIMEOUT"
	NetworkReadNodeUnreachable = "NODE_UNREACHABLE"
	NetworkReadSourceFailed    = "SOURCE_READ_FAILED"
	NetworkReadOutputLimit     = "OUTPUT_LIMIT"
	NetworkReadInvalidResponse = "INVALID_RESPONSE"

	NetworkHealthy  = "HEALTHY"
	NetworkDegraded = "DEGRADED"
	NetworkDown     = "DOWN"
	NetworkUnknown  = "UNKNOWN"
)

type NetworkDetectorPolicy struct {
	Version               int
	InventoryRevision     string
	ExpectedPorts         []NetworkPortKey
	MaxSampleAge          time.Duration
	MaxPollInterval       time.Duration
	FailureConfirmations  int
	RecoveryConfirmations int
}

type NetworkPortAssessment struct {
	State         string
	PhysicalState string
	Key           NetworkPortKey
	Condition     string
	Reason        string
	ReadError     string
	CounterGap    string
	LinkDownDelta uint64
	ObservedAt    time.Time
	FirstBadAt    time.Time
	ConfirmedAt   time.Time
}

// EvaluateNetworkPorts is a deterministic, side-effect-free replay boundary.
// It never uses a successful DCGM scrape as network evidence. Persisting the
// window and incident lifecycle is a later checkpoint; callers must not treat
// this assessment as an alert delivery receipt.
func EvaluateNetworkPorts(policy NetworkDetectorPolicy, polls []NetworkNodePoll, now time.Time) ([]NetworkPortAssessment, error) {
	if policy.Version != 1 || !validAnomalyEntity(policy.InventoryRevision) || policy.MaxSampleAge <= 0 ||
		policy.MaxPollInterval <= 0 || policy.MaxPollInterval > policy.MaxSampleAge ||
		policy.FailureConfirmations < 2 || policy.FailureConfirmations > 10 ||
		policy.RecoveryConfirmations < 2 || policy.RecoveryConfirmations > 10 ||
		len(policy.ExpectedPorts) == 0 || len(policy.ExpectedPorts) > 1024 || len(polls) > 512 || now.IsZero() {
		return nil, fmt.Errorf("invalid network detector policy")
	}
	expected := make(map[NetworkPortKey]struct{}, len(policy.ExpectedPorts))
	nodes := make(map[string]struct{})
	for _, key := range policy.ExpectedPorts {
		if !validAnomalyEntity(key.Node) || !validAnomalyEntity(key.Device) || key.Port == 0 || key.Port > 256 {
			return nil, fmt.Errorf("invalid expected network port")
		}
		if _, found := expected[key]; found {
			return nil, fmt.Errorf("duplicate expected network port")
		}
		expected[key] = struct{}{}
		nodes[key.Node] = struct{}{}
	}
	byNode := make(map[string][]NetworkNodePoll, len(nodes))
	totalReadings := 0
	for _, poll := range polls {
		if _, found := nodes[poll.Node]; !found || poll.InventoryRevision != policy.InventoryRevision || poll.ObservedAt.IsZero() || poll.ObservedAt.After(now) ||
			poll.Outcome != NetworkPollComplete && poll.Outcome != NetworkPollAuthUnavailable &&
				poll.Outcome != NetworkPollNodeUnreachable && poll.Outcome != NetworkPollReadFailed ||
			!validNetworkReadError(poll.ReadError) {
			return nil, fmt.Errorf("invalid network poll")
		}
		if poll.Outcome == NetworkPollComplete && (poll.BootID == "" || poll.ReadError != "") {
			return nil, fmt.Errorf("complete network poll needs boot identity")
		}
		if poll.Outcome != NetworkPollComplete && len(poll.Ports) != 0 {
			return nil, fmt.Errorf("failed network poll cannot contain ports")
		}
		totalReadings += len(poll.Ports)
		if len(poll.Ports) > 256 || totalReadings > 8192 {
			return nil, fmt.Errorf("network poll has too many ports")
		}
		seen := make(map[NetworkPortKey]struct{}, len(poll.Ports))
		for _, port := range poll.Ports {
			if port.Key.Node != poll.Node {
				return nil, fmt.Errorf("invalid network poll port")
			}
			if _, found := seen[port.Key]; found {
				return nil, fmt.Errorf("duplicate network poll port")
			}
			seen[port.Key] = struct{}{}
		}
		byNode[poll.Node] = append(byNode[poll.Node], poll)
	}
	for node := range byNode {
		slices.SortFunc(byNode[node], func(a, b NetworkNodePoll) int { return a.ObservedAt.Compare(b.ObservedAt) })
		for i := 1; i < len(byNode[node]); i++ {
			if byNode[node][i].ObservedAt.Equal(byNode[node][i-1].ObservedAt) {
				return nil, fmt.Errorf("duplicate network poll time")
			}
		}
	}
	keys := append([]NetworkPortKey(nil), policy.ExpectedPorts...)
	slices.SortFunc(keys, func(a, b NetworkPortKey) int {
		if a.Node != b.Node {
			return strings.Compare(a.Node, b.Node)
		}
		if a.Device != b.Device {
			return strings.Compare(a.Device, b.Device)
		}
		return int(a.Port) - int(b.Port)
	})
	result := make([]NetworkPortAssessment, 0, len(keys))
	for _, key := range keys {
		result = append(result, assessNetworkPort(key, byNode[key.Node], policy, now))
	}
	return result, nil
}

func validNetworkReadError(value string) bool {
	switch value {
	case "", NetworkReadSSHAuthDenied, NetworkReadSSHTimeout, NetworkReadNodeUnreachable,
		NetworkReadSourceFailed, NetworkReadOutputLimit, NetworkReadInvalidResponse:
		return true
	default:
		return false
	}
}

func assessNetworkPort(key NetworkPortKey, polls []NetworkNodePoll, policy NetworkDetectorPolicy, now time.Time) NetworkPortAssessment {
	assessment := NetworkPortAssessment{Key: key, Condition: NetworkUnknown, Reason: "NO_OBSERVATION"}
	if len(polls) == 0 {
		return assessment
	}
	latest := polls[len(polls)-1]
	assessment.ObservedAt = latest.ObservedAt
	assessment.ReadError = latest.ReadError
	if now.Sub(latest.ObservedAt) > policy.MaxSampleAge {
		assessment.Reason = "SOURCE_STALE"
		return assessment
	}
	if latest.Outcome != NetworkPollComplete {
		assessment.Reason = latest.Outcome
		return assessment
	}
	last, found := findNetworkPort(latest.Ports, key)
	assessment.State = last.State
	assessment.PhysicalState = last.PhysicalState
	bad := !found || strings.TrimSpace(last.LinkLayer) == "InfiniBand" &&
		(strings.TrimSpace(last.State) != "4: ACTIVE" || strings.TrimSpace(last.PhysicalState) != "5: LinkUp")
	if found && strings.TrimSpace(last.LinkLayer) != "InfiniBand" {
		assessment.Reason = "LINK_LAYER_MISMATCH"
		return assessment
	}
	if bad {
		assessment.Condition, assessment.Reason = NetworkDegraded, "PORT_NOT_ACTIVE"
		if !found {
			assessment.Reason = "PORT_MISSING"
		}
		count := 0
		for i := len(polls) - 1; i >= 0; i-- {
			poll := polls[i]
			if poll.Outcome != NetworkPollComplete || now.Sub(poll.ObservedAt) > policy.MaxSampleAge || poll.BootID != latest.BootID ||
				(i < len(polls)-1 && polls[i+1].ObservedAt.Sub(poll.ObservedAt) > policy.MaxPollInterval) {
				break
			}
			port, exists := findNetworkPort(poll.Ports, key)
			if exists && (strings.TrimSpace(port.LinkLayer) != "InfiniBand" ||
				strings.TrimSpace(port.State) == "4: ACTIVE" && strings.TrimSpace(port.PhysicalState) == "5: LinkUp") {
				break
			}
			count++
			assessment.FirstBadAt = poll.ObservedAt
			if count >= policy.FailureConfirmations {
				assessment.Condition = NetworkDown
				assessment.ConfirmedAt = latest.ObservedAt
			}
		}
		return assessment
	}
	if len(polls) > 1 {
		previous := polls[len(polls)-2]
		if previous.Outcome == NetworkPollComplete && now.Sub(previous.ObservedAt) <= policy.MaxSampleAge &&
			latest.ObservedAt.Sub(previous.ObservedAt) <= policy.MaxPollInterval {
			if previous.BootID != latest.BootID {
				assessment.Reason = "BOOT_ID_CHANGED"
				return assessment
			}
			before, existed := findNetworkPort(previous.Ports, key)
			if existed && before.LinkDowned != nil && last.LinkDowned != nil {
				if *last.LinkDowned < *before.LinkDowned {
					assessment.Reason = "COUNTER_RESET"
					return assessment
				}
				if *last.LinkDowned > *before.LinkDowned {
					assessment.Condition, assessment.Reason = NetworkDegraded, "LINK_DOWNED_INCREASE"
					assessment.LinkDownDelta = *last.LinkDowned - *before.LinkDowned
					assessment.FirstBadAt = previous.ObservedAt
					assessment.ConfirmedAt = latest.ObservedAt
					return assessment
				}
			} else {
				assessment.CounterGap = "COUNTER_UNAVAILABLE"
			}
		} else {
			assessment.CounterGap = "UNCOMPARABLE_POLL_GAP"
		}
	}
	healthy := 0
	for i := len(polls) - 1; i >= 0; i-- {
		poll := polls[i]
		if poll.Outcome != NetworkPollComplete || now.Sub(poll.ObservedAt) > policy.MaxSampleAge || poll.BootID != latest.BootID ||
			(i < len(polls)-1 && polls[i+1].ObservedAt.Sub(poll.ObservedAt) > policy.MaxPollInterval) {
			break
		}
		port, exists := findNetworkPort(poll.Ports, key)
		if !exists || strings.TrimSpace(port.LinkLayer) != "InfiniBand" ||
			strings.TrimSpace(port.State) != "4: ACTIVE" || strings.TrimSpace(port.PhysicalState) != "5: LinkUp" {
			break
		}
		healthy++
	}
	if healthy < policy.RecoveryConfirmations {
		assessment.Condition, assessment.Reason = NetworkDegraded, "RECOVERY_CONFIRMATION_PENDING"
		return assessment
	}
	assessment.Condition, assessment.Reason = NetworkHealthy, "ACTIVE_LINK_UP"
	return assessment
}

func findNetworkPort(ports []NetworkPortReading, key NetworkPortKey) (NetworkPortReading, bool) {
	for _, port := range ports {
		if port.Key == key {
			return port, true
		}
	}
	return NetworkPortReading{}, false
}

// NetworkBondReading describes only the explicitly approved local management
// interface. Carrier does not prove switch reachability or LACP forwarding.
type NetworkBondReading struct {
	Name      string                    `json:"name"`
	Present   bool                      `json:"present"`
	Mode      string                    `json:"mode"`
	Carrier   string                    `json:"carrier"`
	OperState string                    `json:"operstate"`
	ReadError string                    `json:"read_error,omitempty"`
	Members   []NetworkInterfaceReading `json:"members"`
}
type NetworkInterfaceReading struct {
	Name      string  `json:"name"`
	Present   bool    `json:"present"`
	Carrier   string  `json:"carrier"`
	OperState string  `json:"operstate"`
	RXErrors  *uint64 `json:"rx_errors,omitempty"`
	TXErrors  *uint64 `json:"tx_errors,omitempty"`
	RXDropped *uint64 `json:"rx_dropped,omitempty"`
	TXDropped *uint64 `json:"tx_dropped,omitempty"`
}
