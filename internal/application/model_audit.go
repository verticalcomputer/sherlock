package application

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

var (
	ErrModelCallInFlight         = errors.New("model call is already reserved")
	ErrModelCallAlreadyAttempted = errors.New("model call was already attempted")
	ErrModelCallOutcomeUnknown   = errors.New("model call outcome is unknown")
)

// ModelCallKind identifies the logical model role. Planning and synthesis are
// audited separately even when a deployment routes them to the same provider.
type ModelCallKind string

const (
	ModelCallPlanning  ModelCallKind = "PLANNING"
	ModelCallSynthesis ModelCallKind = "SYNTHESIS"
)

// ModelCallOutcome contains only safe, bounded metadata. Model payload bodies
// remain outside this row and are referenced through immutable evidence IDs.
type ModelCallOutcome string

const (
	ModelCallSucceeded ModelCallOutcome = "SUCCEEDED"
	ModelCallRejected  ModelCallOutcome = "REJECTED"
	ModelCallFailed    ModelCallOutcome = "FAILED"
)

type ModelCallAudit struct {
	CallID              string
	CallKey             string
	InvestigationID     domain.InvestigationID
	ClusterID           domain.ClusterID
	Kind                ModelCallKind
	Provider            string
	Model               string
	ModelConfigVersion  string
	PromptSchemaVersion string
	ToolSchemaVersion   string
	InputTokens         int64
	OutputTokens        int64
	CostMicros          int64
	Latency             time.Duration
	Outcome             ModelCallOutcome
	ReasonCode          string
	InputEvidenceID     domain.EvidenceID
	OutputEvidenceID    domain.EvidenceID
	OccurredAt          time.Time
}

func (audit ModelCallAudit) Validate() error {
	if !validAuditToken(audit.CallID) || !validAuditToken(audit.CallKey) ||
		audit.InvestigationID == "" || audit.ClusterID == "" ||
		!validAuditToken(audit.Provider) || !validAuditToken(audit.Model) ||
		!validAuditToken(audit.ModelConfigVersion) ||
		!validAuditToken(audit.PromptSchemaVersion) ||
		!validAuditToken(audit.ToolSchemaVersion) || audit.OccurredAt.IsZero() {
		return fmt.Errorf("model call audit attribution is incomplete")
	}
	if audit.Kind != ModelCallPlanning && audit.Kind != ModelCallSynthesis {
		return fmt.Errorf("unknown model call kind %q", audit.Kind)
	}
	if audit.Outcome != ModelCallSucceeded && audit.Outcome != ModelCallRejected && audit.Outcome != ModelCallFailed {
		return fmt.Errorf("unknown model call outcome %q", audit.Outcome)
	}
	if audit.InputTokens < 0 || audit.OutputTokens < 0 || audit.CostMicros < 0 || audit.Latency < 0 {
		return fmt.Errorf("model call usage cannot be negative")
	}
	if audit.Outcome == ModelCallSucceeded && audit.ReasonCode != "" {
		return fmt.Errorf("successful model call cannot have a reason code")
	}
	if audit.Outcome != ModelCallSucceeded && !validAuditToken(audit.ReasonCode) {
		return fmt.Errorf("unsuccessful model call requires a safe reason code")
	}
	if (audit.InputEvidenceID == "") != (audit.OutputEvidenceID == "") && audit.InputEvidenceID == "" {
		return fmt.Errorf("model output evidence requires input evidence")
	}
	if (audit.InputEvidenceID != "" && !validAuditToken(string(audit.InputEvidenceID))) ||
		(audit.OutputEvidenceID != "" && !validAuditToken(string(audit.OutputEvidenceID))) {
		return fmt.Errorf("model payload evidence identifier is invalid")
	}
	return nil
}

type ModelCallAuditSink interface {
	AppendModelCallAudit(context.Context, ModelCallAudit) error
}

type ModelCallReservationStatus string

const (
	ModelCallReserved       ModelCallReservationStatus = "RESERVED"
	ModelCallSucceededState ModelCallReservationStatus = "SUCCEEDED"
	ModelCallRejectedState  ModelCallReservationStatus = "REJECTED"
	ModelCallFailedState    ModelCallReservationStatus = "FAILED"
	ModelCallUnknownState   ModelCallReservationStatus = "OUTCOME_UNKNOWN"
)

// ModelCallReservationStore establishes a durable, unique barrier before a
// provider request. Completion happens only after required evidence and audit
// persistence, so an expired reservation is an uncertain outcome, never a retry.
type ModelCallReservationStore interface {
	ReserveModelCall(context.Context, domain.InvestigationID, domain.ClusterID, string, ModelCallKind, time.Time, time.Time) error
	CompleteModelCall(context.Context, domain.InvestigationID, string, ModelCallReservationStatus, time.Time) error
}

func validAuditToken(value string) bool {
	if len(value) < 1 || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' || character == '/' || character == ':' {
			continue
		}
		return false
	}
	return true
}
