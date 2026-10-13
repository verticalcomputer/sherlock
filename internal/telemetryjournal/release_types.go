package telemetryjournal

import (
	"context"
	"errors"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

var ErrReceiptExpired = errors.New("telemetry journal receipt expired")
var ErrReleaseSealed = errors.New("telemetry journal ownership range sealed")

type ReleaseAuthorization struct{ SignerActive bool }

// ReleaseVerifier checks negotiated capabilities and current scoped authority
// before replay. VerifyRelease authenticates the original signed Request only;
// SealRelease/AdmitRelease separately validate the complete manifest and proof.
// Completed records retain signed requests after compacting selected manifests.
// Node local signing checks do not grant remote enrollment.
type ReleaseVerifier interface {
	AuthorizeRetirement(context.Context, Scope) error
	VerifyRelease(context.Context, telemetry.ReleaseEnvelope) (ReleaseAuthorization, error)
	VerifyCompletion(context.Context, telemetry.NodeReleaseCompletion) (ReleaseAuthorization, error)
}
type ReleaseRecord struct {
	Request           telemetry.ReleaseRequest            `json:"request"`
	Manifest          telemetry.ReleaseManifest           `json:"manifest"`
	Phase             string                              `json:"phase"`
	Admission         *telemetry.ReleaseAdmissionReceipt  `json:"admission,omitempty"`
	Prepared          *telemetry.CloudRetirementReceipt   `json:"prepared,omitempty"`
	Commit            *telemetry.GatewayReleaseCommit     `json:"commit,omitempty"`
	Final             *telemetry.GatewayRetirementReceipt `json:"final,omitempty"`
	AllocatorSHA256   string                              `json:"allocator_sha256,omitempty"`
	Completion        *telemetry.NodeReleaseCompletion    `json:"completion,omitempty"`
	CompletionReceipt *telemetry.NodeCompletionReceipt    `json:"completion_receipt,omitempty"`
}
type ReleaseProposal struct {
	FromSequence, ThroughSequence string
	Manifest                      telemetry.ReleaseManifest
}
type OwnershipLookup struct {
	Disposition string
	Entry       *Entry
}

const (
	OwnershipExact       = "EXACT"
	OwnershipTransferred = "KNOWN_TRANSFERRED"
	OwnershipLoss        = "EXPLICIT_LOSS"
	OwnershipExpired     = "RECEIPT_EXPIRED"
)
const MaxRetainedReceiptSessions = 4096
