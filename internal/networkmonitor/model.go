// Package networkmonitor defines the explicitly enrolled recurring IB source.
// It samples kernel state; it cannot establish lossless transient-event coverage.
package networkmonitor

import (
	"fmt"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/networkprobe"
)

const Interval = time.Minute
const MaxAge = 3 * time.Minute
const MaxGap = 90 * time.Second

type ExpectedPort struct {
	Key      application.NetworkPortKey
	NodeGUID string
}
type Enrollment struct {
	ClusterID            string
	CollectorID          string
	Revision             string
	Ports                []ExpectedPort
	ManagementRevision   string
	ManagementEnrolledAt time.Time
	ManagementEnabled    bool
	Bonds                []ExpectedBond
}
type Cycle struct {
	DurationMS int64
	Revision   string
	Polls      []application.NetworkNodePoll
}
type Summary struct {
	Enrolled        bool                                `json:"enrolled"`
	Revision        string                              `json:"revision,omitempty"`
	InfiniBandState string                              `json:"infiniband_state"`
	State           string                              `json:"state"`
	IntervalSeconds int                                 `json:"interval_seconds"`
	ExpectedNodes   int                                 `json:"expected_nodes"`
	ExpectedPorts   int                                 `json:"expected_ports"`
	HealthyPorts    int                                 `json:"healthy_ports"`
	DownPorts       int                                 `json:"down_ports"`
	UnknownPorts    int                                 `json:"unknown_ports"`
	DegradedPorts   int                                 `json:"degraded_ports"`
	LastObservedAt  *time.Time                          `json:"last_observed_at,omitempty"`
	LastReceivedAt  *time.Time                          `json:"last_received_at,omitempty"`
	CycleDurationMS int64                               `json:"cycle_duration_ms"`
	OpenEpisodes    int                                 `json:"open_episodes"`
	PendingAlerts   int                                 `json:"pending_alerts"`
	FailedAlerts    int                                 `json:"failed_alerts"`
	Management      ManagementSummary                   `json:"management"`
	Details         []application.NetworkPortAssessment `json:"details,omitempty"`
}

func Validate(e Enrollment) error {
	if e.ClusterID != "fixture2-zone2" || len(e.CollectorID) < 8 || len(e.CollectorID) > 128 || len(e.Revision) < 8 || len(e.Revision) > 128 || strings.ContainsAny(e.Revision+e.CollectorID, " \r\n\x00") || len(e.Ports) != 112 {
		return fmt.Errorf("invalid network enrollment")
	}
	nodes := map[string]int{}
	keys := map[application.NetworkPortKey]bool{}
	guids := map[string]bool{}
	for _, p := range e.Ports {
		approved := false
		for _, n := range networkprobe.FixtureNetworkNodes {
			if p.Key.Node == n {
				approved = true
			}
		}
		if !approved || p.Key.Port != 1 || !strings.Contains("|mlx5_0|mlx5_1|mlx5_4|mlx5_5|mlx5_6|mlx5_7|mlx5_8|mlx5_9|", "|"+p.Key.Device+"|") || len(p.NodeGUID) != 19 || keys[p.Key] || guids[p.NodeGUID] {
			return fmt.Errorf("invalid enrolled port identity")
		}
		for i, c := range p.NodeGUID {
			if i == 4 || i == 9 || i == 14 {
				if c != ':' {
					return fmt.Errorf("invalid port GUID")
				}
			} else if !strings.ContainsRune("0123456789abcdef", c) {
				return fmt.Errorf("invalid port GUID")
			}
		}
		keys[p.Key] = true
		guids[p.NodeGUID] = true
		nodes[p.Key.Node]++
	}
	for _, n := range networkprobe.FixtureNetworkNodes {
		if nodes[n] != 8 {
			return fmt.Errorf("incomplete network enrollment")
		}
	}
	return validateManagementEnrollment(e)
}
func Assess(e Enrollment, polls []application.NetworkNodePoll, now time.Time) ([]application.NetworkPortAssessment, error) {
	keys := make([]application.NetworkPortKey, 0, len(e.Ports))
	guid := map[application.NetworkPortKey]string{}
	for _, p := range e.Ports {
		keys = append(keys, p.Key)
		guid[p.Key] = p.NodeGUID
	}
	// An identity mismatch also breaks the confirmation window. Merely
	// overriding the latest display would allow one restored sample to recover
	// an episode by counting an earlier reading from a different adapter.
	normalized := append([]application.NetworkNodePoll(nil), polls...)
	for i, p := range normalized {
		if p.Outcome == application.NetworkPollComplete {
			for _, v := range p.Ports {
				if expected, ok := guid[v.Key]; ok && expected != v.NodeGUID {
					normalized[i].Outcome = application.NetworkPollReadFailed
					normalized[i].ReadError = application.NetworkReadInvalidResponse
					normalized[i].Ports = nil
					break
				}
			}
		}
	}
	results, err := application.EvaluateNetworkPorts(application.NetworkDetectorPolicy{Version: 1, InventoryRevision: e.Revision, ExpectedPorts: keys, MaxSampleAge: MaxAge, MaxPollInterval: MaxGap, FailureConfirmations: 2, RecoveryConfirmations: 2}, normalized, now)
	if err != nil {
		return nil, err
	}
	latest := map[string]application.NetworkNodePoll{}
	for _, p := range polls {
		if p.ObservedAt.After(latest[p.Node].ObservedAt) {
			latest[p.Node] = p
		}
	}
	for i := range results {
		a := &results[i]
		p := latest[a.Key.Node]
		if p.Outcome == application.NetworkPollComplete && now.Sub(p.ObservedAt) <= MaxAge {
			for _, v := range p.Ports {
				if v.Key == a.Key && v.NodeGUID != guid[v.Key] {
					a.Condition = application.NetworkUnknown
					a.Reason = "PORT_IDENTITY_CHANGED"
				}
			}
		}
	}
	return results, nil
}
func ValidateCycle(e Enrollment, c Cycle, now time.Time) error {
	if c.Revision != e.Revision || len(c.Polls) != 14 || c.DurationMS < 0 || c.DurationMS > 65000 {
		return fmt.Errorf("invalid network cycle")
	}
	nodes := map[string]bool{}
	for _, p := range c.Polls {
		if nodes[p.Node] || p.InventoryRevision != e.Revision || p.ObservedAt.After(now.Add(2*time.Second)) || now.Sub(p.ObservedAt) > MaxAge {
			return fmt.Errorf("invalid network poll time or identity")
		}
		nodes[p.Node] = true
		if p.Outcome == application.NetworkPollComplete && (len(p.BootID) < 8 || len(p.BootID) > 64) {
			return fmt.Errorf("invalid boot identity")
		}
		if p.Outcome != application.NetworkPollComplete && p.ReadError == "" {
			return fmt.Errorf("missing source failure code")
		}
	}
	if err := validateManagementPolls(e, c.Polls); err != nil {
		return err
	}
	_, err := Assess(e, c.Polls, now.Add(2*time.Second))
	return err
}
