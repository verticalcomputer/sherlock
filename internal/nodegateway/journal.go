package nodegateway

import (
	"context"
	"errors"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetryjournal"
)

// GatewayAdmission must be installed as both queue verifiers, with
// RequireSessions=true. No permissive default can acknowledge node data.
type GatewayAdmission struct{ authority *Authority }

func NewGatewayAdmission(authority *Authority) (*GatewayAdmission, error) {
	if authority == nil {
		return nil, telemetry.ErrInvalid
	}
	return &GatewayAdmission{authority: authority}, nil
}
func (a *GatewayAdmission) Verify(ctx context.Context, body []byte) (telemetryjournal.Envelope, error) {
	var envelope telemetryjournal.Envelope
	batch, err := telemetry.DecodeNodeBatch(body, "")
	if err != nil {
		return envelope, telemetry.ErrInvalid
	}
	grant, err := a.authority.grant(ctx, batch.Key.EnrollmentID)
	if err != nil {
		return envelope, telemetry.ErrUnauthorized
	}
	if telemetry.ValidateBatchForGrant(batch, grant, a.authority.now()) != nil {
		return envelope, telemetry.ErrUnauthorized
	}
	key, err := signer(grant, batch.SigningKeyID)
	if err != nil || telemetry.VerifyBatchSignature(batch, key) != nil {
		return envelope, telemetry.ErrUnauthorized
	}
	sources := make([]string, 0, len(batch.Sources))
	lane := telemetryjournal.Contact
	var losses []telemetry.SessionLoss
	for _, source := range batch.Sources {
		sources = append(sources, source.SourceID)
		if len(source.Records) > 0 {
			lane = telemetryjournal.Data
		}
		for _, loss := range source.Loss {
			losses = append(losses, telemetry.SessionLoss{SourceID: source.SourceID, Range: loss})
		}
	}
	if len(losses) > 0 {
		lane = telemetryjournal.Loss
	}
	return telemetryjournal.Envelope{Key: batch.Key, Digest: batch.Digest, CreatedAt: batch.CreatedAt, Lane: lane, Sources: sources, Loss: losses, BootID: batch.BootID, SigningKeyID: batch.SigningKeyID, EnrollmentRevision: batch.EnrollmentRevision}, nil
}
func (a *GatewayAdmission) VerifySession(ctx context.Context, m telemetry.SessionMessage) (telemetryjournal.SessionAuthorization, error) {
	grant, err := a.authority.grant(ctx, m.EnrollmentID)
	if err != nil {
		return telemetryjournal.SessionAuthorization{}, telemetry.ErrUnauthorized
	}
	if telemetry.ValidateSessionForGrant(m, grant, a.authority.now()) != nil {
		return telemetryjournal.SessionAuthorization{}, telemetry.ErrUnauthorized
	}
	for _, key := range grant.Keys {
		if key.ID == m.SigningKeyID {
			return telemetryjournal.SessionAuthorization{SignerActive: key.State == "ACTIVE"}, nil
		}
	}
	return telemetryjournal.SessionAuthorization{}, telemetry.ErrUnauthorized
}

// JournalIngress adapts already-open, independently scoped gateway queues. The
// constructor does not enforce aggregate disk quotas or start a service; callers
// must complete that resource gate before using a client installation candidate.
type JournalIngress struct {
	queues map[string]*telemetryjournal.Queue
}

func NewJournalIngress(queues map[string]*telemetryjournal.Queue) (*JournalIngress, error) {
	if len(queues) == 0 || len(queues) > 4096 {
		return nil, telemetry.ErrInvalid
	}
	cloned := make(map[string]*telemetryjournal.Queue, len(queues))
	for id, queue := range queues {
		if !identityID(id) || queue == nil {
			return nil, telemetry.ErrInvalid
		}
		binding := queue.Binding()
		if binding.Role != telemetryjournal.Gateway || !binding.RequireSessions || binding.Scope.EnrollmentID != id {
			return nil, telemetry.ErrInvalid
		}
		cloned[id] = queue
	}
	return &JournalIngress{queues: cloned}, nil
}
func (j *JournalIngress) RegisterSession(ctx context.Context, m telemetry.SessionMessage) (telemetry.SessionReceipt, error) {
	queue := j.queues[m.EnrollmentID]
	if queue == nil {
		return telemetry.SessionReceipt{}, telemetry.ErrUnauthorized
	}
	receipt, err := queue.RegisterSession(ctx, m)
	return receipt, journalError(err)
}
func (j *JournalIngress) Accept(ctx context.Context, b telemetry.NodeBatch, body []byte) (telemetry.Receipt, error) {
	queue := j.queues[b.Key.EnrollmentID]
	if queue == nil {
		return telemetry.Receipt{}, telemetry.ErrUnauthorized
	}
	// The queue independently decodes/signature-checks the immutable bytes and
	// validates its persisted session before the matching-receipt lookup.
	receipt, err := queue.Put(ctx, body)
	return receipt, journalError(err)
}
func journalError(err error) error {
	if err == nil {
		return nil
	}
	for _, safe := range []error{telemetry.ErrUnauthorized, telemetry.ErrInvalid, telemetry.ErrConflict, telemetry.ErrBackpressure, telemetry.ErrReplayExpired} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	switch {
	case errors.Is(err, telemetryjournal.ErrConflict):
		return telemetry.ErrConflict
	case errors.Is(err, telemetryjournal.ErrCapacity):
		return telemetry.ErrBackpressure
	case errors.Is(err, telemetryjournal.ErrInvalid):
		return telemetry.ErrInvalid
	case errors.Is(err, telemetryjournal.ErrLost):
		return telemetry.ErrReplayExpired
	case errors.Is(err, telemetryjournal.ErrReceiptExpired), errors.Is(err, telemetryjournal.ErrReleaseSealed):
		return telemetry.ErrReplayExpired
	default:
		return telemetry.ErrUnavailable
	}
}
