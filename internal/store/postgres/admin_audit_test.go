package postgres

import (
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adminui"
)

func TestValidAdminAuditEvent(t *testing.T) {
	valid := adminui.AuditEvent{
		Kind: adminui.EventDashboardViewed, Outcome: adminui.OutcomeSucceeded,
		ReasonCode: "healthy", RequestID: "request-1", OccurredAt: time.Now(),
		SessionFingerprint: make([]byte, 32),
	}
	if !validAdminAuditEvent(valid) {
		t.Fatal("valid event rejected")
	}
	for _, mutate := range []func(*adminui.AuditEvent){
		func(event *adminui.AuditEvent) { event.Kind = "UNKNOWN" },
		func(event *adminui.AuditEvent) { event.Outcome = "UNKNOWN" },
		func(event *adminui.AuditEvent) { event.OccurredAt = time.Time{} },
		func(event *adminui.AuditEvent) { event.SessionFingerprint = make([]byte, 31) },
	} {
		candidate := valid
		mutate(&candidate)
		if validAdminAuditEvent(candidate) {
			t.Fatalf("invalid event accepted: %+v", candidate)
		}
	}
}
