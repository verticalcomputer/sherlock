// Package gatewaytelemetry forwards immutable locally owned telemetry through
// the existing authenticated collector boundary. It performs no source reads.
package gatewaytelemetry

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetryjournal"
)

type Queue interface {
	NextForDrain(context.Context, uint64) (telemetryjournal.Entry, bool, error)
	NextForDrainExcludingSessions(context.Context, uint64, []string) (telemetryjournal.Entry, bool, error)
	SessionOpen(context.Context, string) (telemetry.SessionMessage, error)
	SessionMessages(context.Context) ([]telemetry.SessionMessage, error)
	Read(context.Context, telemetry.BatchKey) ([]byte, error)
	Acknowledge(context.Context, telemetry.Receipt, string) error
}
type Cloud interface {
	RegisterSession(context.Context, telemetry.SessionMessage) (telemetry.SessionReceipt, error)
	SubmitBatch(context.Context, telemetry.NodeBatch, string) (telemetry.CloudReceipt, error)
}
type Observer interface {
	Delivery(enrollmentID, code string)
}
type cursor struct {
	turn     uint64
	failures uint8
	next     time.Time
}
type Runtime struct {
	mu           sync.Mutex
	queues       map[string]Queue
	ids          []string
	cloud        Cloud
	observer     Observer
	state        map[string]cursor
	offset       int
	now          func() time.Time
	lifecycle    map[string]map[string]bool
	blocked      map[string]map[string]time.Time
	releaseAfter map[string]string
}

type ownershipBlocked struct{ cause error }

func (e ownershipBlocked) Error() string { return "telemetry ownership blocked" }
func (e ownershipBlocked) Unwrap() error { return e.cause }

func New(queues map[string]Queue, cloud Cloud, observer Observer) (*Runtime, error) {
	if len(queues) == 0 || len(queues) > 4096 || cloud == nil {
		return nil, telemetry.ErrInvalid
	}
	owned := map[string]Queue{}
	lifecycle := map[string]map[string]bool{}
	blocked := map[string]map[string]time.Time{}
	ids := make([]string, 0, len(queues))
	for id, q := range queues {
		if !telemetry.ValidIdentifier(id) || q == nil {
			return nil, telemetry.ErrInvalid
		}
		owned[id] = q
		lifecycle[id] = map[string]bool{}
		blocked[id] = map[string]time.Time{}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return &Runtime{queues: owned, ids: ids, cloud: cloud, observer: observer, state: map[string]cursor{}, lifecycle: lifecycle, blocked: blocked, releaseAfter: map[string]string{}, now: time.Now}, nil
}

// Run advances serial passes. Cancellation joins in-flight requests before
// returning; the caller may then close journal storage safely.
func (r *Runtime) Run(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		_, _ = r.Pass(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Pass selects at most four nodes in round-robin order, one operation per node.
// Lifecycle, authority and batch handoffs share the six-second pass deadline.
// A failed node backs off independently; its immutable bytes remain owned.
func (r *Runtime) Pass(ctx context.Context) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	bounded, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	type result struct {
		id        string
		delivered bool
		err       error
	}
	results := make(chan result, 4)
	started := 0
	at := r.now()
	for examined := 0; examined < len(r.ids) && started < 4; examined++ {
		id := r.ids[r.offset]
		r.offset = (r.offset + 1) % len(r.ids)
		state := r.state[id]
		if at.Before(state.next) {
			continue
		}
		started++
		go func(id string, turn uint64) {
			delivered, err := r.drain(bounded, id, turn)
			results <- result{id, delivered, err}
		}(id, state.turn)
	}
	delivered := 0
	var failures []error
	for received := 0; received < started; received++ {
		result := <-results
		state := r.state[result.id]
		// Every attempted turn advances fairness, including a rejected old batch.
		// Failed authority never releases or deletes its journal ownership.
		state.turn++
		code := "EMPTY"
		if result.err != nil {
			if state.failures < 6 {
				state.failures++
			}
			delay := time.Second * time.Duration(1<<state.failures)
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
			state.next = r.now().Add(delay)
			code = "DELIVERY_UNAVAILABLE"
			var blocked ownershipBlocked
			if errors.As(result.err, &blocked) {
				code = "OWNERSHIP_BLOCKED"
			}
			failures = append(failures, telemetry.ErrUnavailable)
		} else {
			state.failures = 0
			state.next = time.Time{}
			if result.delivered {
				delivered++
				code = "DELIVERED"
			}
			if !result.delivered && len(r.blocked[result.id]) > 0 {
				code = "OWNERSHIP_BLOCKED"
			}
		}
		r.state[result.id] = state
		if r.observer != nil {
			r.observer.Delivery(result.id, code)
		}
	}
	if ctx.Err() != nil {
		failures = append(failures, ctx.Err())
	}
	return delivered, errors.Join(failures...)
}
func (r *Runtime) drain(ctx context.Context, id string, turn uint64) (bool, error) {
	queue := r.queues[id]
	if turn%5 == 4 {
		if handled, progressed, err := r.drainRetirement(ctx, id); handled {
			return progressed, err
		}
		if pruned, err := r.pruneRetirement(ctx, id); pruned || err != nil {
			return pruned, err
		}
	}
	// At most eight OPEN and eight FINALIZE facts exist per enrollment. Replay
	// lifecycle facts after every gateway restart; the cloud's immutable receipts
	// make this safe without introducing a second durable acknowledgement journal.
	messages, err := queue.SessionMessages(ctx)
	if err != nil || len(messages) > 16 {
		return false, telemetry.ErrUnavailable
	}
	sort.Slice(messages, func(i, j int) bool {
		if messages[i].Kind != messages[j].Kind {
			return messages[i].Kind == "OPEN"
		}
		a, _ := strconv.ParseUint(messages[i].SessionEpoch, 10, 64)
		b, _ := strconv.ParseUint(messages[j].SessionEpoch, 10, 64)
		return a < b
	})
	known := r.lifecycle[id]
	current := make(map[string]bool, len(messages))
	currentEpoch := make(map[string]bool, 8)
	for _, message := range messages {
		current[message.Digest] = true
		currentEpoch[message.SessionEpoch] = true
	}
	for digest := range known {
		if !current[digest] {
			delete(known, digest)
		}
	}
	for epoch := range r.blocked[id] {
		if !currentEpoch[epoch] {
			delete(r.blocked[id], epoch)
		}
	}
	for _, message := range messages {
		if message.EnrollmentID != id || telemetry.ValidateSessionMessage(message) != nil {
			return false, telemetry.ErrConflict
		}
		if known[message.Digest] {
			continue
		}
		if r.now().Before(r.blocked[id][message.SessionEpoch]) {
			continue
		}
		receipt, err := r.cloud.RegisterSession(ctx, message)
		if err != nil {
			return false, r.blockSession(id, message.SessionEpoch, err)
		}
		if !validSessionReceipt(receipt, message) {
			return false, telemetry.ErrConflict
		}
		if handoff, ok := queue.(interface {
			AcknowledgeSession(context.Context, telemetry.SessionMessage, telemetry.SessionReceipt) error
		}); ok {
			if err := handoff.AcknowledgeSession(ctx, message, receipt); err != nil {
				return false, err
			}
			if message.Kind == "FINALIZE" {
				if err := compactGatewaySessions(ctx, queue); err != nil {
					return false, err
				}
			}
		}
		known[message.Digest] = true
		delete(r.blocked[id], message.SessionEpoch)
		return true, nil
	}
	var excluded []string
	for epoch, until := range r.blocked[id] {
		if r.now().Before(until) {
			excluded = append(excluded, epoch)
		}
	}
	sort.Strings(excluded)
	entry, found, err := queue.NextForDrainExcludingSessions(ctx, turn, excluded)
	if err != nil {
		return false, err
	}
	if !found {
		_, progressed, err := r.drainRetirement(ctx, id)
		return progressed, err
	}
	open, err := queue.SessionOpen(ctx, entry.Key.SessionEpoch)
	if err != nil {
		return false, err
	}
	lifecycle, err := r.cloud.RegisterSession(ctx, open)
	if err != nil {
		return false, r.blockSession(id, entry.Key.SessionEpoch, err)
	}
	if !validSessionReceipt(lifecycle, open) || open.ClusterID != entry.Key.ClusterID || open.NodeID != entry.Key.NodeID || open.EnrollmentID != entry.Key.EnrollmentID || open.SessionEpoch != entry.Key.SessionEpoch || open.SessionID != entry.Key.SessionID {
		return false, telemetry.ErrConflict
	}
	if handoff, ok := queue.(interface {
		AcknowledgeSession(context.Context, telemetry.SessionMessage, telemetry.SessionReceipt) error
	}); ok {
		if err := handoff.AcknowledgeSession(ctx, open, lifecycle); err != nil {
			return false, err
		}
	}
	wire, err := queue.Read(ctx, entry.Key)
	if err != nil {
		return false, err
	}
	batch, err := telemetry.DecodeNodeBatch(wire, "")
	if err != nil || batch.Key != entry.Key || batch.Digest != entry.Digest {
		return false, telemetry.ErrConflict
	}
	receipt, err := r.cloud.SubmitBatch(ctx, batch, entry.Receipt.ID)
	if err != nil {
		return false, r.blockSession(id, entry.Key.SessionEpoch, err)
	}
	if receipt.ProtocolVersion != 1 || receipt.Durability != "CLOUD" || receipt.Key != entry.Key || receipt.Digest != entry.Digest || receipt.GatewayReceiptID != entry.Receipt.ID || !telemetry.ValidIdentifier(receipt.ID) || receipt.StoredAt.IsZero() || !receipt.HistoryOnly {
		return false, telemetry.ErrConflict
	}
	ack := telemetry.Receipt{ProtocolVersion: receipt.ProtocolVersion, ID: receipt.ID, Key: receipt.Key, Digest: receipt.Digest, StoredAt: receipt.StoredAt, Durability: receipt.Durability}
	if err := queue.Acknowledge(ctx, ack, receipt.GatewayReceiptID); err != nil {
		return false, err
	}
	return true, nil
}

// Closed authority/protocol failures are retried after a bounded pause for the
// affected session. Its owned bytes remain in the original journal, while valid
// sessions continue. Restart discards these hints and rechecks cloud authority.
func (r *Runtime) blockSession(id, epoch string, err error) error {
	for _, closed := range []error{telemetry.ErrUnauthorized, telemetry.ErrConflict, telemetry.ErrInvalid, telemetry.ErrReplayExpired} {
		if errors.Is(err, closed) {
			if len(r.blocked[id]) >= 8 && r.blocked[id][epoch].IsZero() {
				return telemetry.ErrBackpressure
			}
			r.blocked[id][epoch] = r.now().Add(30 * time.Second)
			return ownershipBlocked{closed}
		}
	}
	return err
}

func validSessionReceipt(r telemetry.SessionReceipt, m telemetry.SessionMessage) bool {
	return r.ProtocolVersion == 1 && r.Durability == "CLOUD" && r.ClusterID == m.ClusterID && r.NodeID == m.NodeID && r.EnrollmentID == m.EnrollmentID && r.EnrollmentRevision == m.EnrollmentRevision && r.SessionEpoch == m.SessionEpoch && r.SessionID == m.SessionID && r.BootID == m.BootID && r.Kind == m.Kind && r.Digest == m.Digest && telemetry.ValidIdentifier(r.ID) && !r.StoredAt.IsZero() && r.Finalized == (m.Kind == "FINALIZE") && (!r.Retired || m.Kind == "FINALIZE")
}
