package nodetelemetry

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetryjournal"
)

func LinuxBootID() (string, error) {
	b, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil || len(b) > 128 {
		return "", ErrState
	}
	id := strings.TrimSpace(string(b))
	if !telemetry.ValidIdentifier(id) {
		return "", ErrState
	}
	return id, nil
}

func Open(ctx context.Context, c Config) (*Runtime, error) {
	if c.Interval == 0 {
		c.Interval = 30 * time.Second
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.BootID == nil {
		c.BootID = LinuxBootID
	}
	if !filepath.IsAbs(c.Root) || filepath.Clean(c.Root) != c.Root || c.Gateway == nil || c.Interval < 10*time.Second || c.Interval > 24*time.Hour {
		return nil, ErrInvalid
	}
	c.Scope.SourceIDs = append([]string(nil), c.Scope.SourceIDs...)
	sort.Strings(c.Scope.SourceIDs)
	c.Scope.Keys = append([]telemetry.NodeKey(nil), c.Scope.Keys...)
	c.SigningKey = append([]byte(nil), c.SigningKey...)
	v, e := newLocalVerifier(c.Scope, c.SigningKeyID, c.SigningKey)
	if e != nil {
		return nil, e
	}
	boot, e := c.BootID()
	if e != nil || !telemetry.ValidIdentifier(boot) {
		return nil, ErrState
	}
	limits := telemetryjournal.NodeLimits()
	if c.limits != nil {
		limits = *c.limits
	}
	q, e := telemetryjournal.Open(c.Root, telemetryjournal.Options{Role: telemetryjournal.Node, Scope: telemetryjournal.Scope{ClusterID: c.Scope.ClusterID, NodeID: c.Scope.NodeID, EnrollmentID: c.Scope.EnrollmentID}, SourceIDs: c.Scope.SourceIDs, RequireSessions: true, Verifier: v, SessionVerifier: v, ReleaseVerifier: v, PublicKeys: c.Scope.Keys, Limits: limits, Now: c.Now})
	if e != nil {
		return nil, ErrState
	}
	r := &Runtime{config: c, q: q, boot: boot, maxAge: limits.MaxAge, limiter: tokenBucket{tokens: 1 << 20, last: time.Now()}}
	keys, e := q.GetHistoricalPublicKeys(ctx)
	if e != nil {
		_ = q.Close()
		return nil, ErrState
	}
	for _, key := range keys {
		v.historical[key.ID] = key
	}
	if e = r.load(ctx, v); e == nil {
		_, e = r.now()
	}
	if e == nil {
		if err := r.q.Expire(ctx, r.config.Now()); err != nil {
			e = ErrState
		}
	}
	if e == nil {
		e = r.recoverPending(ctx)
	}
	if e == nil {
		e = r.syncLosses(ctx)
	}
	if e == nil {
		e = r.ensureSession(ctx)
		if errors.Is(e, ErrCapacity) && len(r.state.Sessions) == 8 && r.state.Sessions[7].Final != nil {
			if _, supported := c.Gateway.(RetirementGateway); supported {
				e = nil
			}
		}
	}
	if e != nil {
		_ = q.Close()
		return nil, e
	}
	return r, nil
}

func (r *Runtime) recoverPending(ctx context.Context) error {
	if r.state.Pending == nil {
		return nil
	}
	k := r.state.Pending.Key
	ownership, e := r.q.LookupOwnership(ctx, k)
	if errors.Is(e, telemetryjournal.ErrNotFound) {
		if e = r.addGap(ctx, k, r.config.Scope.SourceIDs, "LOCAL_COMMIT_INTERRUPTED"); e != nil {
			return e
		}
	} else if e != nil {
		return ErrState
	} else {
		if ownership.Disposition == telemetryjournal.OwnershipTransferred || ownership.Disposition == telemetryjournal.OwnershipExpired {
			s := clone(r.state)
			s.Pending = nil
			return r.save(ctx, s)
		}
		if ownership.Entry == nil {
			return ErrState
		}
		entry := *ownership.Entry
		switch entry.State {
		case "OWNED", "TRANSFERRED":
		case "LOST":
			if entry.Loss == nil {
				return ErrState
			}
			if e = r.addGap(ctx, k, entry.Loss.Sources, entry.Loss.Reason); e != nil {
				return e
			}
		default:
			return ErrState
		}
	}
	s := clone(r.state)
	s.Pending = nil
	return r.save(ctx, s)
}
func (r *Runtime) addGap(ctx context.Context, k telemetry.BatchKey, sources []string, reason string) error {
	facts := len(sources)
	for _, g := range r.state.Gaps {
		facts += len(g.SourceIDs)
		if g.Key == k {
			ordered := append([]string(nil), sources...)
			sort.Strings(ordered)
			if g.Reason != reason || strings.Join(g.SourceIDs, "\x00") != strings.Join(ordered, "\x00") {
				return ErrState
			}
			return nil
		}
	}
	if facts > telemetry.MaxLossRanges || len(r.state.Gaps) >= 256 || wireReason(reason) == "" {
		return ErrCapacity
	}
	g := signedGap{Key: k, SourceIDs: append([]string(nil), sources...), Reason: reason, SigningKeyID: r.config.SigningKeyID}
	sort.Strings(g.SourceIDs)
	signGap(&g, r.config.SigningKey)
	s := clone(r.state)
	s.Gaps = append(s.Gaps, g)
	return r.save(ctx, s)
}
func (r *Runtime) syncLosses(ctx context.Context) error {
	for {
		rows, next, more, e := r.q.LocalLosses(ctx, r.state.LossCursor, 128)
		if e != nil {
			return ErrState
		}
		for _, row := range rows {
			if e = r.addGap(ctx, row.Loss.AffectedKey, row.Loss.Sources, row.Loss.Reason); e != nil {
				return e
			}
			s := clone(r.state)
			s.LossCursor = row.Ordinal
			if e = r.save(ctx, s); e != nil {
				return e
			}
		}
		if !more {
			return nil
		}
		if next <= r.state.LossCursor && len(rows) == 0 {
			return ErrState
		}
	}
}

func (r *Runtime) now() (time.Time, error) {
	at := r.config.Now().Round(0).UTC()
	if at.Year() < 2020 || at.Year() > 2200 || !r.state.LastCreatedAt.IsZero() && at.Before(r.state.LastCreatedAt) {
		return time.Time{}, ErrClock
	}
	return at, nil
}
func (r *Runtime) ensureSession(ctx context.Context) error {
	// Replay a possibly interrupted local lifecycle commit using exact bytes.
	for _, x := range r.state.Sessions {
		if _, e := r.q.RegisterSession(ctx, x.Open); e != nil {
			return ErrState
		}
		if x.Final != nil {
			if _, e := r.q.RegisterSession(ctx, *x.Final); e != nil {
				return ErrState
			}
		}
	}
	if len(r.state.Sessions) > 0 {
		last := r.state.Sessions[len(r.state.Sessions)-1]
		if last.Open.BootID == r.boot && last.Open.SigningKeyID == r.config.SigningKeyID && last.Final == nil {
			return nil
		}
	}
	at, e := r.now()
	if e != nil {
		return e
	}
	s := clone(r.state)
	if len(s.Sessions) > 0 && s.Sessions[len(s.Sessions)-1].Final == nil {
		i := len(s.Sessions) - 1
		x := &s.Sessions[i]
		m := x.Open
		m.Kind = "FINALIZE"
		m.CreatedAt = at
		m.SigningKeyID = r.config.SigningKeyID
		m.LastAllocatedSequence = x.LastAllocated
		m.Digest = ""
		m.Signature = ""
		m.Loss = nil
		for _, g := range s.Gaps {
			if g.Key.SessionEpoch == x.Open.SessionEpoch && g.Carrier == nil {
				for _, source := range g.SourceIDs {
					m.Loss = append(m.Loss, telemetry.SessionLoss{SourceID: source, Range: gapRange(g, source)})
				}
			}
		}
		if len(m.Loss) > telemetry.MaxLossRanges {
			return ErrCapacity
		}
		if e = telemetry.SignSessionMessage(&m, r.config.SigningKey); e != nil {
			return ErrState
		}
		x.Final = &m
		if e = r.save(ctx, s); e != nil {
			return e
		}
		if _, e = r.q.RegisterSession(ctx, m); e != nil {
			return ErrState
		}
		s = clone(r.state)
	}
	if len(s.Sessions) >= 8 {
		return ErrCapacity
	}
	id, e := randomID("session-")
	if e != nil {
		return e
	}
	if s.BaseEpoch > ^uint64(0)-uint64(len(s.Sessions))-1 {
		return ErrCapacity
	}
	m := telemetry.SessionMessage{ProtocolVersion: 1, Kind: "OPEN", ClusterID: r.config.Scope.ClusterID, NodeID: r.config.Scope.NodeID, EnrollmentID: r.config.Scope.EnrollmentID, EnrollmentRevision: 1, SessionEpoch: strconv.FormatUint(s.BaseEpoch+uint64(len(s.Sessions))+1, 10), SessionID: id, BootID: r.boot, SigningKeyID: r.config.SigningKeyID, CreatedAt: at}
	if e = telemetry.SignSessionMessage(&m, r.config.SigningKey); e != nil {
		return ErrState
	}
	s.Sessions = append(s.Sessions, sessionState{Open: m, LastAllocated: "0", ReleasedThrough: "0"})
	s.LastCreatedAt = at
	if e = r.save(ctx, s); e != nil {
		return e
	}
	if _, e = r.q.RegisterSession(ctx, m); e != nil {
		return ErrState
	}
	return nil
}
func gapRange(g signedGap, source string) telemetry.LossRange {
	hash := sha256.Sum256([]byte(g.Digest + "\x00" + source))
	return telemetry.LossRange{ID: "gap-" + hex.EncodeToString(hash[:]), AffectedKey: g.Key, ThroughSequence: g.Key.Sequence, Reason: wireReason(g.Reason), CountKnown: false}
}

// CollectOnce allocates before reading the synthetic source. Errors never free
// an allocated sequence; pending recovery must prove sealing or preserve loss.
func (r *Runtime) CollectOnce(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrState
	}
	// Put may evict older OWNED bytes at capacity. Do not allocate, expire or
	// seal while a transfer is in flight: its late receipt must not race loss.
	if r.draining {
		r.collectionPending = true
		return ErrBusy
	}
	r.collectionPending = false
	if e := r.recoverPending(ctx); e != nil {
		return e
	}
	if e := r.q.Expire(ctx, r.config.Now()); e != nil {
		return ErrState
	}
	if e := r.syncLosses(ctx); e != nil {
		return e
	}
	if e := r.ensureSession(ctx); e != nil {
		if errors.Is(e, ErrCapacity) && len(r.state.Sessions) == 8 && r.state.Sessions[7].Final != nil {
			if _, supported := r.config.Gateway.(RetirementGateway); supported {
				return ErrBusy
			}
		}
		return e
	}
	at, e := r.now()
	if e != nil {
		return e
	}
	s := clone(r.state)
	i := len(s.Sessions) - 1
	x := &s.Sessions[i]
	last, _ := decimal(x.LastAllocated, true)
	if last == ^uint64(0) {
		return ErrCapacity
	}
	seq := last + 1
	x.LastAllocated = strconv.FormatUint(seq, 10)
	k := telemetry.BatchKey{ClusterID: r.config.Scope.ClusterID, NodeID: r.config.Scope.NodeID, EnrollmentID: r.config.Scope.EnrollmentID, SessionEpoch: x.Open.SessionEpoch, SessionID: x.Open.SessionID, Sequence: x.LastAllocated}
	s.Pending = &pendingAllocation{Key: k}
	if e = r.save(ctx, s); e != nil {
		return e
	}
	if e = r.fail("allocation_committed"); e != nil {
		return ErrState
	}
	b := telemetry.NodeBatch{ProtocolVersion: 1, Key: k, EnrollmentRevision: 1, InventoryRevisionID: r.config.Scope.InventoryRevisionID, BootID: r.boot, SigningKeyID: r.config.SigningKeyID, AgentVersion: r.config.Scope.AgentVersion, BuildSHA256: r.config.Scope.BuildSHA256, CreatedAt: at}
	for index, id := range r.config.Scope.SourceIDs {
		frame, err := telemetry.NewFixtureFrame(id, k.ClusterID, k.NodeID, "e"+k.SessionEpoch+"-s"+k.Sequence+"-f"+strconv.Itoa(index), at, seq)
		if err != nil {
			return ErrState
		}
		for _, g := range r.state.Gaps {
			if g.Carrier == nil {
				for _, source := range g.SourceIDs {
					if source == id {
						frame.Loss = append(frame.Loss, gapRange(g, id))
					}
				}
			}
		}
		b.Sources = append(b.Sources, frame)
	}
	if e = telemetry.SignBatch(&b, r.config.SigningKey); e != nil {
		return ErrCapacity
	}
	wire, e := json.Marshal(b)
	if e != nil {
		return ErrState
	}
	if _, e = r.q.Put(ctx, wire); e != nil {
		if errors.Is(e, telemetryjournal.ErrCapacity) {
			return ErrCapacity
		}
		return ErrState
	}
	if e = r.fail("batch_sealed"); e != nil {
		return ErrState
	}
	s = clone(r.state)
	s.Pending = nil
	s.LastCreatedAt = at
	return r.save(ctx, s)
}

// DrainOnce makes at most one network request. Network waits never hold the
// allocator lock; exact signed lifecycle facts precede dependent batches.
func (r *Runtime) DrainOnce(ctx context.Context) (bool, error) {
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
	var message *telemetry.SessionMessage
	for _, s := range r.state.Sessions {
		if s.OpenAck == nil {
			m := s.Open
			message = &m
			break
		}
		if s.Final != nil && s.FinalAck == nil {
			m := *s.Final
			message = &m
			break
		}
	}
	if message != nil {
		wire, _ := json.Marshal(message)
		r.mu.Unlock()
		if e := r.limiter.wait(ctx, len(wire)); e != nil {
			return false, e
		}
		receipt, e := r.config.Gateway.RegisterSession(ctx, *message)
		if e != nil {
			return false, e
		}
		if !validSessionReceipt(receipt, *message) {
			return false, ErrState
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if e = r.q.AcknowledgeSession(ctx, *message, receipt); e != nil {
			return false, ErrState
		}
		s := clone(r.state)
		index, ok := sessionIndex(s, message.SessionEpoch)
		if !ok {
			return false, ErrState
		}
		if message.Kind == "OPEN" {
			s.Sessions[index].OpenAck = &receipt
		} else {
			s.Sessions[index].FinalAck = &receipt
		}
		if e = r.save(ctx, s); e != nil {
			return false, e
		}
		return true, nil
	}
	entry, found, e := r.q.NextForDrain(ctx, r.turn)
	r.turn++
	if e != nil {
		r.mu.Unlock()
		return false, ErrState
	}
	if !found {
		r.mu.Unlock()
		return false, nil
	}
	if !entry.StoredAt.After(r.config.Now().Add(-r.maxAge)) {
		if e = r.q.RecordLoss(ctx, entry.Key, "NODE_EXPIRED"); e == nil {
			e = r.syncLosses(ctx)
		}
		r.mu.Unlock()
		if e != nil {
			return false, ErrState
		}
		return true, nil
	}
	wire, e := r.q.Read(ctx, entry.Key)
	r.mu.Unlock()
	if e != nil {
		return false, ErrState
	}
	if e = r.limiter.wait(ctx, len(wire)); e != nil {
		return false, e
	}
	receipt, e := r.config.Gateway.SubmitBatch(ctx, wire)
	if e != nil {
		return false, e
	}
	if !validBatchReceipt(receipt, entry.Key, entry.Digest) {
		return false, ErrState
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e = r.q.Acknowledge(ctx, receipt, ""); e != nil {
		return false, ErrState
	}
	if e = r.fail("gateway_ack_committed"); e != nil {
		return false, ErrState
	}
	b, e := telemetry.DecodeNodeBatch(wire, "")
	if e != nil {
		return false, ErrState
	}
	s := clone(r.state)
	for i, g := range s.Gaps {
		if g.Carrier != nil {
			continue
		}
		matched := true
		for _, source := range g.SourceIDs {
			found := false
			for _, frame := range b.Sources {
				if frame.SourceID == source {
					for _, l := range frame.Loss {
						if l.ID == gapRange(g, source).ID {
							found = true
						}
					}
				}
			}
			matched = matched && found
		}
		if matched {
			s.Gaps[i].Carrier = &carrierProof{Key: entry.Key, Digest: entry.Digest, Receipt: receipt}
		}
	}
	if e = r.save(ctx, s); e != nil {
		return false, e
	}
	return true, nil
}

func (r *Runtime) Run(ctx context.Context) error {
	r.mu.Lock()
	if r.running || r.closed {
		r.mu.Unlock()
		return ErrRunning
	}
	r.running = true
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.running = false; r.mu.Unlock() }()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	fatal := make(chan error, 3)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		timer := time.NewTimer(0)
		defer timer.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-timer.C:
				if e := r.CollectOnce(runCtx); e != nil && runCtx.Err() == nil {
					if errors.Is(e, ErrBusy) {
						timer.Reset(time.Second)
						continue
					}
					if r.config.Report != nil {
						r.config.Report(e)
					}
					fatal <- e
					return
				}
				timer.Reset(r.config.Interval)
			}
		}
	}()
	if _, supported := r.config.Gateway.(RetirementGateway); supported {
		workers.Add(1)
		go func() {
			defer workers.Done()
			backoff := time.Second
			timer := time.NewTimer(0)
			defer timer.Stop()
			for {
				select {
				case <-runCtx.Done():
					return
				case <-timer.C:
				}
				progress, e := r.RetireOnce(runCtx)
				if runCtx.Err() != nil {
					return
				}
				delay := time.Second
				if e != nil {
					if r.config.Report != nil {
						r.config.Report(safeGatewayError(e))
					}
					if errors.Is(e, ErrState) || errors.Is(e, ErrCapacity) || errors.Is(e, ErrClock) || errors.Is(e, telemetry.ErrUnauthorized) || errors.Is(e, telemetry.ErrConflict) || errors.Is(e, telemetry.ErrReplayExpired) || errors.Is(e, telemetry.ErrInvalid) {
						fatal <- safeRetirementError(e)
						return
					}
					delay = jitter(backoff)
					if backoff < 30*time.Second {
						backoff *= 2
						if backoff > 30*time.Second {
							backoff = 30 * time.Second
						}
					}
				} else {
					backoff = time.Second
					if !progress {
						delay = 5 * time.Second
					}
				}
				timer.Reset(delay)
			}
		}()
	}
	go func() {
		defer workers.Done()
		backoff := time.Second
		for {
			if runCtx.Err() != nil {
				return
			}
			progress, e := r.DrainOnce(runCtx)
			if runCtx.Err() != nil {
				return
			}
			delay := time.Second
			if e != nil {
				if r.config.Report != nil {
					r.config.Report(safeGatewayError(e))
				}
				if errors.Is(e, ErrState) || errors.Is(e, ErrCapacity) {
					fatal <- e
					return
				}
				if errors.Is(e, telemetry.ErrUnauthorized) || errors.Is(e, telemetry.ErrConflict) || errors.Is(e, telemetry.ErrReplayExpired) || errors.Is(e, telemetry.ErrInvalid) {
					fatal <- safeGatewayError(e)
					return
				}
				delay = jitter(backoff)
				if backoff < 30*time.Second {
					backoff *= 2
					if backoff > 30*time.Second {
						backoff = 30 * time.Second
					}
				}
			} else {
				backoff = time.Second
				if progress {
					continue
				}
			}
			timer := time.NewTimer(delay)
			select {
			case <-runCtx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-timer.C:
			}
		}
	}()
	var result error
	select {
	case <-ctx.Done():
		result = ctx.Err()
	case result = <-fatal:
	}
	cancel()
	workers.Wait()
	return result
}
func safeRetirementError(e error) error {
	if errors.Is(e, ErrState) {
		return ErrState
	}
	if errors.Is(e, ErrCapacity) {
		return ErrCapacity
	}
	if errors.Is(e, ErrClock) {
		return ErrClock
	}
	return safeGatewayError(e)
}
func safeGatewayError(e error) error {
	switch {
	case errors.Is(e, telemetry.ErrUnauthorized):
		return telemetry.ErrUnauthorized
	case errors.Is(e, telemetry.ErrConflict):
		return telemetry.ErrConflict
	case errors.Is(e, telemetry.ErrBackpressure):
		return telemetry.ErrBackpressure
	case errors.Is(e, telemetry.ErrReplayExpired):
		return telemetry.ErrReplayExpired
	case errors.Is(e, telemetry.ErrInvalid):
		return telemetry.ErrInvalid
	default:
		return telemetry.ErrUnavailable
	}
}

func jitter(base time.Duration) time.Duration {
	var value [1]byte
	if _, err := rand.Read(value[:]); err != nil {
		return base
	}
	delay := base*4/5 + time.Duration(value[0])*base*2/5/255
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	return delay
}
func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running || r.draining {
		return ErrRunning
	}
	if r.closed {
		return nil
	}
	r.closed = true
	for i := range r.config.SigningKey {
		r.config.SigningKey[i] = 0
	}
	return r.q.Close()
}

type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func (b *tokenBucket) wait(ctx context.Context, n int) error {
	if n < 0 || n > telemetry.MaxBatchBytes {
		return ErrCapacity
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		b.mu.Lock()
		at := time.Now()
		b.tokens += at.Sub(b.last).Seconds() * 32768
		if b.tokens > 1<<20 {
			b.tokens = 1 << 20
		}
		b.last = at
		if b.tokens >= float64(n) {
			b.tokens -= float64(n)
			b.mu.Unlock()
			return nil
		}
		wait := time.Duration((float64(n) - b.tokens) / 32768 * float64(time.Second))
		b.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}
