package nodegateway

import (
	"context"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetryjournal"
)

func (a *GatewayAdmission) AuthorizeRetirement(ctx context.Context, scope telemetryjournal.Scope) error {
	grant, err := a.authority.grant(ctx, scope.EnrollmentID)
	if err != nil || scope.ClusterID != grant.ClusterID || scope.NodeID != grant.NodeID || scope.EnrollmentID != grant.EnrollmentID {
		return telemetry.ErrUnauthorized
	}
	loader, ok := a.authority.loader.(interface {
		RetirementCapabilities(context.Context, string) (telemetry.RetirementCapabilities, error)
	})
	if !ok {
		return telemetry.ErrUnavailable
	}
	caps, err := loader.RetirementCapabilities(ctx, scope.EnrollmentID)
	if err != nil {
		return err
	}
	return telemetry.ValidateRetirementCapabilities(caps)
}

func (a *GatewayAdmission) VerifyRelease(ctx context.Context, envelope telemetry.ReleaseEnvelope) (telemetryjournal.ReleaseAuthorization, error) {
	request := envelope.Request
	grant, err := a.authority.grant(ctx, request.EnrollmentID)
	if err != nil || telemetry.ValidateReleaseForGrant(request, grant, a.authority.now()) != nil {
		return telemetryjournal.ReleaseAuthorization{}, telemetry.ErrUnauthorized
	}
	for _, key := range grant.Keys {
		if key.ID == request.SigningKeyID {
			return telemetryjournal.ReleaseAuthorization{SignerActive: key.State == "ACTIVE"}, nil
		}
	}
	return telemetryjournal.ReleaseAuthorization{}, telemetry.ErrUnauthorized
}

func (a *GatewayAdmission) VerifyCompletion(ctx context.Context, completion telemetry.NodeReleaseCompletion) (telemetryjournal.ReleaseAuthorization, error) {
	grant, err := a.authority.grant(ctx, completion.Binding.EnrollmentID)
	if err != nil || telemetry.ValidateNodeCompletionForGrant(completion, grant, a.authority.now()) != nil {
		return telemetryjournal.ReleaseAuthorization{}, telemetry.ErrUnauthorized
	}
	for _, key := range grant.Keys {
		if key.ID == completion.SigningKeyID {
			return telemetryjournal.ReleaseAuthorization{SignerActive: key.State == "ACTIVE"}, nil
		}
	}
	return telemetryjournal.ReleaseAuthorization{}, telemetry.ErrUnauthorized
}

func (j *JournalIngress) RetirementCapabilities(ctx context.Context, enrollment string) (telemetry.RetirementCapabilities, error) {
	q := j.queues[enrollment]
	if q == nil {
		return telemetry.RetirementCapabilities{}, telemetry.ErrUnauthorized
	}
	caps, err := q.RetirementCapabilities(ctx)
	return caps, journalError(err)
}

func (j *JournalIngress) ReleaseOwnership(ctx context.Context, envelope telemetry.ReleaseEnvelope) (telemetry.GatewayRetirementReceipt, error) {
	q := j.queues[envelope.Request.EnrollmentID]
	if q == nil {
		return telemetry.GatewayRetirementReceipt{}, telemetry.ErrUnauthorized
	}
	if _, err := q.AdmitRelease(ctx, envelope.Request, envelope.Manifest); err != nil {
		return telemetry.GatewayRetirementReceipt{}, journalError(err)
	}
	state, err := q.ReleaseStatus(ctx, envelope.Request.ReleaseID)
	if err != nil {
		return telemetry.GatewayRetirementReceipt{}, journalError(err)
	}
	if state.Final == nil {
		return telemetry.GatewayRetirementReceipt{}, telemetry.ErrBackpressure
	}
	if state.Request.Digest != envelope.Request.Digest || telemetry.ValidateGatewayRetirementReceipt(*state.Final) != nil || state.Final.Binding != envelope.Request.Binding() {
		return telemetry.GatewayRetirementReceipt{}, telemetry.ErrConflict
	}
	return *state.Final, nil
}

func (j *JournalIngress) CompleteNodeRelease(ctx context.Context, completion telemetry.NodeReleaseCompletion) (telemetry.NodeCompletionReceipt, error) {
	q := j.queues[completion.Binding.EnrollmentID]
	if q == nil {
		return telemetry.NodeCompletionReceipt{}, telemetry.ErrUnauthorized
	}
	if err := q.AdmitNodeCompletion(ctx, completion); err != nil {
		return telemetry.NodeCompletionReceipt{}, journalError(err)
	}
	state, err := q.ReleaseStatus(ctx, completion.Binding.ReleaseID)
	if err != nil {
		return telemetry.NodeCompletionReceipt{}, journalError(err)
	}
	if state.CompletionReceipt == nil {
		return telemetry.NodeCompletionReceipt{}, telemetry.ErrBackpressure
	}
	if state.Completion == nil || state.Completion.Digest != completion.Digest {
		return telemetry.NodeCompletionReceipt{}, telemetry.ErrConflict
	}
	return *state.CompletionReceipt, nil
}
