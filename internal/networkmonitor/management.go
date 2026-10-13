package networkmonitor

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/networkprobe"
)

type ExpectedBond struct {
	Node, Name, Mode string
	Members          []string
}
type ManagementAssessment struct {
	Node       string    `json:"node"`
	Interface  string    `json:"interface"`
	Bond       string    `json:"bond"`
	Condition  string    `json:"condition"`
	Reason     string    `json:"reason"`
	Carrier    string    `json:"carrier"`
	OperState  string    `json:"operstate"`
	ReadError  string    `json:"read_error,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
	RXErrors   *uint64   `json:"rx_errors,omitempty"`
	TXErrors   *uint64   `json:"tx_errors,omitempty"`
	RXDropped  *uint64   `json:"rx_dropped,omitempty"`
	TXDropped  *uint64   `json:"tx_dropped,omitempty"`
}
type ManagementSummary struct {
	Enrolled        bool                   `json:"enrolled"`
	Revision        string                 `json:"revision,omitempty"`
	State           string                 `json:"state"`
	ExpectedBonds   int                    `json:"expected_bonds"`
	ExpectedLinks   int                    `json:"expected_links"`
	ExpectedMembers int                    `json:"expected_members"`
	HealthyLinks    int                    `json:"healthy_links"`
	DownLinks       int                    `json:"down_links"`
	UnknownLinks    int                    `json:"unknown_links"`
	PendingLinks    int                    `json:"pending_links"`
	Details         []ManagementAssessment `json:"details,omitempty"`
}

func validateManagementEnrollment(e Enrollment) error {
	if e.ManagementRevision == "" && len(e.Bonds) == 0 && !e.ManagementEnabled {
		return nil
	}
	if len(e.ManagementRevision) < 8 || len(e.ManagementRevision) > 128 || strings.ContainsAny(e.ManagementRevision, " \r\n\x00") || len(e.Bonds) != 14 {
		return fmt.Errorf("invalid management enrollment")
	}
	seen := map[string]bool{}
	for _, b := range e.Bonds {
		if !slices.Contains(networkprobe.FixtureNetworkNodes, b.Node) || seen[b.Node] || b.Name != "bond0" || b.Mode != "802.3ad 4" || len(b.Members) != 2 || !slices.Equal(b.Members, []string{"enp55s0f0np0", "enp55s0f1np1"}) {
			return fmt.Errorf("invalid management identity")
		}
		seen[b.Node] = true
	}
	return nil
}
func validateManagementPolls(e Enrollment, polls []application.NetworkNodePoll) error {
	for _, p := range polls {
		// Absent enrollment accepts bounded read-only discovery, never alerts on it.
		if p.ManagementRevision != "" && (!e.ManagementEnabled || p.ManagementRevision != e.ManagementRevision) {
			return fmt.Errorf("wrong management revision")
		}
		if len(p.Bonds) > 1 || (p.Outcome != application.NetworkPollComplete && len(p.Bonds) > 0) {
			return fmt.Errorf("invalid management source")
		}
		for _, b := range p.Bonds {
			if b.Name != "bond0" || len(b.Mode) > 32 || !validLink(b.Carrier, b.OperState, b.Present, b.ReadError) || len(b.Members) > 16 || (b.ReadError != "" && b.ReadError != application.NetworkReadSourceFailed && b.ReadError != application.NetworkReadInvalidResponse) {
				return fmt.Errorf("invalid management reading")
			}
			seen := map[string]bool{}
			for _, m := range b.Members {
				if !validInterface(m.Name) || seen[m.Name] || !validLink(m.Carrier, m.OperState, m.Present, b.ReadError) {
					return fmt.Errorf("invalid management member")
				}
				seen[m.Name] = true
			}
		}
	}
	return nil
}
func validInterface(n string) bool {
	if len(n) == 0 || len(n) > 32 {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
func validLink(carrier, state string, present bool, readError string) bool {
	if readError != "" || !present {
		return len(carrier) <= 8 && len(state) <= 32
	}
	return (carrier == "0" || carrier == "1") && slices.Contains([]string{"up", "down", "unknown", "dormant", "lowerlayerdown", "notpresent", "testing"}, state)
}
func AssessManagement(e Enrollment, polls []application.NetworkNodePoll, now time.Time) (ManagementSummary, error) {
	result := ManagementSummary{Enrolled: e.ManagementEnabled, Revision: e.ManagementRevision, State: application.NetworkUnknown}
	if !e.ManagementEnabled {
		return result, nil
	}
	if err := validateManagementEnrollment(e); err != nil {
		return result, err
	}
	if err := validateManagementPolls(e, polls); err != nil {
		return result, err
	}
	result.ExpectedBonds = len(e.Bonds)
	result.ExpectedMembers = 2 * len(e.Bonds)
	result.ExpectedLinks = 3 * len(e.Bonds)
	result.State = application.NetworkHealthy
	for _, b := range e.Bonds {
		var history []application.NetworkNodePoll
		for _, p := range polls {
			if p.Node == b.Node {
				if !e.ManagementEnrolledAt.IsZero() && p.ObservedAt.Before(e.ManagementEnrolledAt) {
					p.ManagementRevision = ""
				}
				history = append(history, p)
			}
		}
		slices.SortFunc(history, func(a, b application.NetworkNodePoll) int { return a.ObservedAt.Compare(b.ObservedAt) })
		for _, iface := range append([]string{b.Name}, b.Members...) {
			a := assessManagementLink(b, iface, e.ManagementRevision, history, now)
			result.Details = append(result.Details, a)
			switch a.Condition {
			case application.NetworkHealthy:
				result.HealthyLinks++
			case application.NetworkDown:
				result.DownLinks++
			case application.NetworkUnknown:
				result.UnknownLinks++
			default:
				result.PendingLinks++
			}
		}
	}
	if result.DownLinks > 0 || result.PendingLinks > 0 {
		result.State = application.NetworkDegraded
	}
	if result.UnknownLinks > 0 {
		result.State = application.NetworkUnknown
	}
	return result, nil
}
func managementReading(expected ExpectedBond, iface, revision string, p application.NetworkNodePoll, now time.Time) ManagementAssessment {
	a := ManagementAssessment{Node: expected.Node, Interface: iface, Bond: expected.Name, Condition: application.NetworkUnknown, Reason: "NO_OBSERVATION", ObservedAt: p.ObservedAt, ReadError: p.ReadError}
	if p.ObservedAt.IsZero() {
		return a
	}
	if now.Sub(p.ObservedAt) > MaxAge {
		a.Reason = "SOURCE_STALE"
		return a
	}
	if p.Outcome != application.NetworkPollComplete {
		a.Reason = p.Outcome
		return a
	}
	if p.ManagementRevision != revision {
		a.Reason = "MANAGEMENT_NOT_OBSERVED"
		return a
	}
	if len(p.Bonds) != 1 {
		a.Reason = "MANAGEMENT_READ_FAILED"
		a.ReadError = application.NetworkReadInvalidResponse
		return a
	}
	b := p.Bonds[0]
	if b.ReadError != "" {
		a.Reason = "MANAGEMENT_READ_FAILED"
		a.ReadError = b.ReadError
		return a
	}
	a.Condition = application.NetworkDown
	a.Reason = "INTERFACE_MISSING"
	if !b.Present {
		return a
	}
	if b.Mode != expected.Mode {
		a.Condition = application.NetworkUnknown
		a.Reason = "BOND_MODE_CHANGED"
		return a
	}
	// A new or moved member breaks the reviewed identity rather than proving a
	// carrier failure. A removed expected member remains a provable missing link.
	for _, m := range b.Members {
		if !slices.Contains(expected.Members, m.Name) {
			a.Condition = application.NetworkUnknown
			a.Reason = "BOND_MEMBERS_CHANGED"
			return a
		}
	}
	if iface == b.Name {
		a.Carrier = b.Carrier
		a.OperState = b.OperState
	} else {
		found := false
		for _, m := range b.Members {
			if m.Name == iface {
				found = m.Present
				a.Carrier = m.Carrier
				a.OperState = m.OperState
				a.RXErrors = m.RXErrors
				a.TXErrors = m.TXErrors
				a.RXDropped = m.RXDropped
				a.TXDropped = m.TXDropped
			}
		}
		if !found {
			return a
		}
	}
	if a.Carrier == "1" && (a.OperState == "unknown" || a.OperState == "testing" || a.OperState == "notpresent") {
		a.Condition = application.NetworkUnknown
		a.Reason = "OPERSTATE_UNSUPPORTED"
		return a
	}
	a.Reason = "CARRIER_OR_OPERSTATE_DOWN"
	if a.Carrier == "1" && a.OperState == "up" {
		a.Condition = application.NetworkHealthy
		a.Reason = "CARRIER_UP"
	}
	return a
}
func assessManagementLink(b ExpectedBond, iface, revision string, history []application.NetworkNodePoll, now time.Time) ManagementAssessment {
	if len(history) == 0 {
		return managementReading(b, iface, revision, application.NetworkNodePoll{}, now)
	}
	latest := history[len(history)-1]
	a := managementReading(b, iface, revision, latest, now)
	if a.Condition == application.NetworkUnknown {
		return a
	}
	condition := a.Condition
	confirmations := 0
	for i := len(history) - 1; i >= 0; i-- {
		p := history[i]
		if p.BootID != latest.BootID || (i < len(history)-1 && history[i+1].ObservedAt.Sub(p.ObservedAt) > MaxGap) {
			break
		}
		v := managementReading(b, iface, revision, p, now)
		if v.Condition != condition {
			break
		}
		confirmations++
	}
	if confirmations < 2 {
		a.Condition = application.NetworkDegraded
		if condition == application.NetworkDown {
			a.Reason = "FAILURE_CONFIRMATION_PENDING"
		} else {
			a.Reason = "RECOVERY_CONFIRMATION_PENDING"
		}
	}
	return a
}
