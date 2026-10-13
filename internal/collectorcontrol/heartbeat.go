package collectorcontrol

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type CapabilityReport struct {
	Name    string
	Version string
}

type CommandPackReport struct {
	PackID       string
	Version      string
	DigestSHA256 string
}

type SourceAvailability string

const (
	SourceUnknown     SourceAvailability = "UNKNOWN"
	SourceAvailable   SourceAvailability = "AVAILABLE"
	SourceUnavailable SourceAvailability = "UNAVAILABLE"
)

type SourceHealthReport struct {
	SourceID     domain.SourceID
	Availability SourceAvailability
	SafeMessage  string
	CheckedAt    time.Time
}

type Heartbeat struct {
	CollectorID  domain.CollectorID
	ProtocolMin  int
	ProtocolMax  int
	Version      string
	BuildCommit  string
	ReportedAt   time.Time
	Capabilities []CapabilityReport
	CommandPacks []CommandPackReport
	SourceHealth []SourceHealthReport
}

type HeartbeatRecorder interface {
	RecordHeartbeat(context.Context, Heartbeat) error
}

func ValidateHeartbeat(report Heartbeat, now time.Time) error {
	minimum, maximum := report.ProtocolRange()
	if minimum < 1 || maximum < minimum || maximum > domain.CollectionProtocolVersion {
		return fmt.Errorf("collector protocol range is unsupported")
	}
	if report.CollectorID == "" || report.ReportedAt.IsZero() || !bounded(report.Version, 1, 128) || !bounded(report.BuildCommit, 0, 128) {
		return fmt.Errorf("collector and bounded version metadata are required")
	}
	if len(report.Capabilities) < 1 || len(report.Capabilities) > 100 || len(report.CommandPacks) > 100 || len(report.SourceHealth) > 100 {
		return fmt.Errorf("heartbeat report counts exceed their bounds")
	}
	capabilities := make(map[string]struct{}, len(report.Capabilities))
	for _, capability := range report.Capabilities {
		if !bounded(capability.Name, 1, 128) || !bounded(capability.Version, 1, 128) {
			return fmt.Errorf("capability name and version are invalid")
		}
		if _, duplicate := capabilities[capability.Name]; duplicate {
			return fmt.Errorf("capability names must be unique")
		}
		capabilities[capability.Name] = struct{}{}
	}
	packs := make(map[string]struct{}, len(report.CommandPacks))
	for _, pack := range report.CommandPacks {
		if !bounded(pack.PackID, 1, 128) || !bounded(pack.Version, 1, 128) || len(pack.DigestSHA256) != 64 {
			return fmt.Errorf("command pack metadata is invalid")
		}
		if _, err := hex.DecodeString(pack.DigestSHA256); err != nil {
			return fmt.Errorf("command pack digest is invalid")
		}
		if _, duplicate := packs[pack.PackID]; duplicate {
			return fmt.Errorf("command pack identifiers must be unique")
		}
		packs[pack.PackID] = struct{}{}
	}
	sources := make(map[domain.SourceID]struct{}, len(report.SourceHealth))
	for _, source := range report.SourceHealth {
		if source.SourceID == "" || source.CheckedAt.IsZero() || len(source.SafeMessage) > 256 {
			return fmt.Errorf("source health metadata is invalid")
		}
		switch source.Availability {
		case SourceUnknown, SourceAvailable, SourceUnavailable:
		default:
			return fmt.Errorf("source availability is invalid")
		}
		if source.CheckedAt.After(now.UTC().Add(5 * time.Minute)) {
			return fmt.Errorf("source health check time is too far in the future")
		}
		if _, duplicate := sources[source.SourceID]; duplicate {
			return fmt.Errorf("source identifiers must be unique")
		}
		sources[source.SourceID] = struct{}{}
	}
	return nil
}

// ProtocolRange preserves v1 reports while making upgrades and downgrades
// replace the capability/protocol snapshot in one transaction.
func (h Heartbeat) ProtocolRange() (int, int) {
	if h.ProtocolMin == 0 && h.ProtocolMax == 0 {
		return 1, 1
	}
	return h.ProtocolMin, h.ProtocolMax
}

func bounded(value string, minimum, maximum int) bool {
	length := len(strings.TrimSpace(value))
	return length >= minimum && length <= maximum
}
