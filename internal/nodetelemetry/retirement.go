package nodetelemetry

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetryjournal"
)

// RetireOnce performs at most one bounded network operation. Capability leases
// are process-local support evidence; every actual handoff still authenticates
// current remote authority. A restart must negotiate again before sealing.
func (r *Runtime) RetireOnce(ctx context.Context) (bool, error) {
	gateway, supported := r.config.Gateway.(RetirementGateway)
	if !supported {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r.drainMu.Lock()
	defer r.drainMu.Unlock()
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return false, ErrState
	}
	if r.collectionPending {
		r.mu.Unlock()
		return false, nil
	}
	r.draining = true
	defer func() { r.mu.Lock(); r.draining = false; r.mu.Unlock() }()
	if !time.Now().Before(r.retirementUntil) {
		r.mu.Unlock()
		capabilities, err := gateway.RetirementCapabilities(ctx)
		if err != nil {
			if errors.Is(err, telemetry.ErrUnauthorized) {
				return false, telemetry.ErrUnauthorized
			}
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			return false, telemetry.ErrBackpressure
		}
		if telemetry.ValidateRetirementCapabilities(capabilities) != nil {
			return false, telemetry.ErrBackpressure
		}
		r.mu.Lock()
		r.retirementUntil = time.Now().Add(30 * time.Second)
		r.mu.Unlock()
		return true, nil
	}
	if err := r.compactSessions(ctx); err != nil {
		r.mu.Unlock()
		return false, err
	}
	records, more, err := r.q.PendingReleases(ctx, "", 8)
	if err != nil || more {
		r.mu.Unlock()
		return false, ErrState
	}
	var record telemetryjournal.ReleaseRecord
	if len(records) > 0 {
		record = records[r.retirementTurn%uint64(len(records))]
		r.retirementTurn++
	} else {
		var found bool
		record, found, err = r.sealNextRelease(ctx)
		if err != nil || !found {
			r.mu.Unlock()
			return false, err
		}
	}
	switch record.Phase {
	case "SEALED", "FINAL_RECEIVED":
		if record.Final != nil {
			err = r.completeLocalRelease(ctx, record.Request, *record.Final)
			r.mu.Unlock()
			return err == nil, err
		}
		envelope := telemetry.ReleaseEnvelope{Request: record.Request, Manifest: record.Manifest}
		wire, err := json.Marshal(envelope)
		r.mu.Unlock()
		if err != nil {
			return false, ErrState
		}
		if err = r.limiter.wait(ctx, len(wire)); err != nil {
			return false, err
		}
		receipt, err := gateway.ReleaseOwnership(ctx, envelope)
		if err != nil {
			return false, err
		}
		if telemetry.ValidateGatewayRetirementReceipt(receipt) != nil || receipt.Binding != record.Request.Binding() {
			return false, ErrState
		}
		r.mu.Lock()
		err = r.completeLocalRelease(ctx, record.Request, receipt)
		r.mu.Unlock()
		return err == nil, err
	case "NODE_COMPACTED", "COMPLETION_SEALED":
		completion := record.Completion
		if completion == nil {
			if record.Final == nil {
				r.mu.Unlock()
				return false, ErrState
			}
			at, err := r.now()
			if err != nil {
				r.mu.Unlock()
				return false, err
			}
			id, err := randomID("completion-")
			if err != nil {
				r.mu.Unlock()
				return false, err
			}
			c := telemetry.NodeReleaseCompletion{ProtocolVersion: 1, ReleaseVersion: 1, ID: id, Binding: record.Request.Binding(), CloudFinalReceiptID: record.Final.CloudFinalReceipt.ID, GatewayRetirementReceiptID: record.Final.ID, SigningKeyID: r.config.SigningKeyID, CreatedAt: at}
			if telemetry.SignNodeCompletion(&c, r.config.SigningKey) != nil || r.q.SealNodeCompletion(ctx, c) != nil {
				r.mu.Unlock()
				return false, ErrState
			}
			if err = r.fail("completion_sealed"); err != nil {
				r.mu.Unlock()
				return false, ErrState
			}
			completion = &c
		}
		wire, err := json.Marshal(completion)
		r.mu.Unlock()
		if err != nil {
			return false, ErrState
		}
		if err = r.limiter.wait(ctx, len(wire)); err != nil {
			return false, err
		}
		receipt, err := gateway.CompleteNodeRelease(ctx, *completion)
		if err != nil {
			return false, err
		}
		if !validCompletionReceipt(receipt, *completion) {
			return false, ErrState
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if err = r.q.ConfirmNodeCompletion(ctx, *completion, receipt); err != nil {
			return false, ErrState
		}
		if err = r.fail("completion_ack_committed"); err != nil {
			return false, ErrState
		}
		if err = r.compactSessions(ctx); err != nil {
			return false, err
		}
		return true, nil
	default:
		r.mu.Unlock()
		return false, ErrState
	}
}

func (r *Runtime) sealNextRelease(ctx context.Context) (telemetryjournal.ReleaseRecord, bool, error) {
	for _, session := range r.state.Sessions {
		if session.OpenAck == nil || session.Final != nil && session.FinalAck == nil {
			continue
		}
		if session.EmptyReleased || session.Final != nil && session.LastAllocated != "0" && session.ReleasedThrough == session.LastAllocated {
			continue
		}
		proposal, err := r.q.BuildReleaseManifest(ctx, session.Open.SessionEpoch, telemetry.MaxReleaseSpan)
		if errors.Is(err, telemetryjournal.ErrNotFound) || errors.Is(err, telemetryjournal.ErrConflict) {
			continue
		}
		if err != nil {
			return telemetryjournal.ReleaseRecord{}, false, ErrState
		}
		through, ok := decimal(proposal.ThroughSequence, true)
		last, _ := decimal(session.LastAllocated, true)
		from, valid := decimal(proposal.FromSequence, true)
		released, _ := decimal(session.ReleasedThrough, true)
		if !ok || !valid || through > last || from == 0 && (through != 0 || session.Final == nil || last != 0 || session.EmptyReleased) || from > 0 && (released == ^uint64(0) || from != released+1) {
			return telemetryjournal.ReleaseRecord{}, false, ErrState
		}
		if r.state.Pending != nil && inReleaseRange(r.state.Pending.Key, session.Open.SessionEpoch, session.Open.SessionID, from, through) {
			continue
		}
		digest, err := telemetry.CanonicalReleaseManifestDigest(proposal.Manifest)
		if err != nil {
			return telemetryjournal.ReleaseRecord{}, false, ErrState
		}
		at, err := r.now()
		if err != nil {
			return telemetryjournal.ReleaseRecord{}, false, err
		}
		id, err := randomID("release-")
		if err != nil {
			return telemetryjournal.ReleaseRecord{}, false, err
		}
		request := telemetry.ReleaseRequest{ProtocolVersion: 1, ReleaseVersion: 1, ReleaseID: id, ClusterID: r.config.Scope.ClusterID, NodeID: r.config.Scope.NodeID, EnrollmentID: r.config.Scope.EnrollmentID, EnrollmentRevision: 1, SessionEpoch: session.Open.SessionEpoch, SessionID: session.Open.SessionID, SigningKeyID: r.config.SigningKeyID, CreatedAt: at, FromSequence: proposal.FromSequence, ThroughSequence: proposal.ThroughSequence, ManifestDigest: hex.EncodeToString(digest[:])}
		if telemetry.SignReleaseRequest(&request, r.config.SigningKey) != nil {
			return telemetryjournal.ReleaseRecord{}, false, ErrState
		}
		if !time.Now().Before(r.retirementUntil) {
			return telemetryjournal.ReleaseRecord{}, false, telemetry.ErrBackpressure
		}
		if err = r.q.SealRelease(ctx, request, proposal.Manifest); err != nil {
			return telemetryjournal.ReleaseRecord{}, false, ErrState
		}
		if err = r.fail("release_sealed"); err != nil {
			return telemetryjournal.ReleaseRecord{}, false, ErrState
		}
		return telemetryjournal.ReleaseRecord{Request: request, Manifest: proposal.Manifest, Phase: "SEALED"}, true, nil
	}
	return telemetryjournal.ReleaseRecord{}, false, nil
}

func inReleaseRange(k telemetry.BatchKey, epoch, id string, from, through uint64) bool {
	sequence, ok := decimal(k.Sequence, false)
	return ok && k.SessionEpoch == epoch && k.SessionID == id && sequence >= from && sequence <= through
}

func (r *Runtime) completeLocalRelease(ctx context.Context, request telemetry.ReleaseRequest, receipt telemetry.GatewayRetirementReceipt) error {
	index, ok := sessionIndex(r.state, request.SessionEpoch)
	if !ok || r.state.Sessions[index].Open.SessionID != request.SessionID {
		return ErrState
	}
	from, _ := decimal(request.FromSequence, true)
	through, _ := decimal(request.ThroughSequence, true)
	s := clone(r.state)
	x := &s.Sessions[index]
	prior, _ := decimal(x.ReleasedThrough, true)
	last, _ := decimal(x.LastAllocated, true)
	if through > last || prior > through || r.state.Pending != nil && inReleaseRange(r.state.Pending.Key, request.SessionEpoch, request.SessionID, from, through) {
		return ErrState
	}
	if from == 0 {
		if x.Final == nil || last != 0 {
			return ErrState
		}
		x.EmptyReleased = true
	} else {
		if prior != through && (prior == ^uint64(0) || from != prior+1) {
			return ErrState
		}
		x.ReleasedThrough = request.ThroughSequence
	}
	retained := s.Gaps[:0]
	for _, gap := range s.Gaps {
		if !inReleaseRange(gap.Key, request.SessionEpoch, request.SessionID, from, through) {
			retained = append(retained, gap)
		}
	}
	s.Gaps = retained
	s, body, err := allocatorBody(s)
	if err != nil {
		return err
	}
	err = r.q.CompleteNodeRelease(ctx, request, receipt, int64(len(body)), func() (string, error) {
		if err := r.writeAllocator(s, body); err != nil {
			return "", err
		}
		if err := r.fail("release_allocator_compacted"); err != nil {
			return "", err
		}
		return s.Checksum, nil
	})
	if err != nil {
		return ErrState
	}
	return nil
}

func (r *Runtime) compactSessions(ctx context.Context) error {
	for _, session := range r.state.Sessions {
		if session.Final != nil && session.FinalAck == nil {
			return nil
		}
	}
	// The journal independently decides the contiguous completed epoch base.
	// Its callback records allocator compaction before committing its own base.
	err := r.q.CompactFinalizedSessions(ctx, allocatorLimit, func(base string) (string, error) {
		n, ok := decimal(base, true)
		if !ok || n < r.state.BaseEpoch || n-r.state.BaseEpoch > uint64(len(r.state.Sessions)) {
			return "", ErrState
		}
		s := clone(r.state)
		remove := int(n - s.BaseEpoch)
		for _, session := range s.Sessions[:remove] {
			if session.Final == nil || session.FinalAck == nil || session.LastAllocated == "0" && !session.EmptyReleased || session.LastAllocated != "0" && session.ReleasedThrough != session.LastAllocated {
				return "", ErrState
			}
			for _, gap := range s.Gaps {
				if gap.Key.SessionEpoch == session.Open.SessionEpoch {
					return "", ErrState
				}
			}
			if s.Pending != nil && s.Pending.Key.SessionEpoch == session.Open.SessionEpoch {
				return "", ErrState
			}
		}
		s.Sessions = append([]sessionState{}, s.Sessions[remove:]...)
		s.BaseEpoch = n
		s, body, err := allocatorBody(s)
		if err != nil {
			return "", err
		}
		if err = r.writeAllocator(s, body); err != nil {
			return "", err
		}
		if err = r.fail("sessions_allocator_compacted"); err != nil {
			return "", err
		}
		return s.Checksum, nil
	})
	if err != nil {
		return ErrState
	}
	return nil
}

func validCompletionReceipt(r telemetry.NodeCompletionReceipt, c telemetry.NodeReleaseCompletion) bool {
	return telemetry.ValidateNodeCompletionReceipt(r) == nil && r.Binding == c.Binding && r.CompletionDigest == c.Digest && r.CloudFinalReceiptID == c.CloudFinalReceiptID && r.GatewayRetirementReceiptID == c.GatewayRetirementReceiptID
}
