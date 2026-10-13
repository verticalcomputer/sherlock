package application

import (
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestLegacyScheduleContract(t *testing.T) {
	schedules := LegacyPrometheusSchedules("cluster", "source", domain.SchedulingLegacy, time.Minute, time.Second, 100, 1024)
	want := map[domain.CollectionOperationID]bool{domain.OperationPrometheusSourceHealth: true, domain.OperationPrometheusGPUIdentity: true, domain.OperationPrometheusGPUUtilization: true, domain.OperationPrometheusGPUXID: true}
	for _, s := range schedules {
		if !want[s.Operation] || s.Revision != 0 || !s.Enabled || s.Interval != time.Minute {
			t.Fatalf("invalid schedule: %+v", s)
		}
		delete(want, s.Operation)
		if err := s.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing operations: %v", want)
	}
}

func TestDesiredScheduleValidation(t *testing.T) {
	base := LegacyPrometheusSchedules("cluster", "source", domain.SchedulingLegacy, time.Minute, time.Second, 100, 1024)[0]
	cases := map[string]func(*domain.DesiredSchedule){
		"zero interval":       func(s *domain.DesiredSchedule) { s.Interval = 0 },
		"fractional interval": func(s *domain.DesiredSchedule) { s.Interval = time.Millisecond },
		"overflow interval":   func(s *domain.DesiredSchedule) { s.Interval = 2147483648 * time.Second },
		"zero timeout":        func(s *domain.DesiredSchedule) { s.Timeout = 0 },
		"fractional timeout":  func(s *domain.DesiredSchedule) { s.Timeout = time.Nanosecond },
		"long timeout":        func(s *domain.DesiredSchedule) { s.Timeout = 2 * time.Minute },
		"negative jitter":     func(s *domain.DesiredSchedule) { s.Jitter = -time.Millisecond },
		"long jitter":         func(s *domain.DesiredSchedule) { s.Jitter = s.Interval },
		"targets":             func(s *domain.DesiredSchedule) { s.MaxTargets = 0 },
		"too many targets":    func(s *domain.DesiredSchedule) { s.MaxTargets = 10001 },
		"bytes":               func(s *domain.DesiredSchedule) { s.MaxBytes = 0 },
		"too many bytes":      func(s *domain.DesiredSchedule) { s.MaxBytes = 10<<20 + 1 },
		"priority":            func(s *domain.DesiredSchedule) { s.Priority = 101 },
		"revision":            func(s *domain.DesiredSchedule) { s.Revision = -1 },
		"mode":                func(s *domain.DesiredSchedule) { s.Mode = "both" },
		"operation":           func(s *domain.DesiredSchedule) { s.Operation = "unknown" },
		"cluster":             func(s *domain.DesiredSchedule) { s.ClusterID = "" },
		"source":              func(s *domain.DesiredSchedule) { s.SourceID = "" },
		"legacy typed":        func(s *domain.DesiredSchedule) { s.Operation = domain.OperationSlurmInventory },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := base
			change(&s)
			if s.Validate() == nil {
				t.Fatal("accepted invalid schedule")
			}
		})
	}
}
