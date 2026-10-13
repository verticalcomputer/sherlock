package collectorruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	ProtocolVersion = 1
	maxChunkBytes   = 256 << 10
	maxChunks       = 64
)

var ErrLeaseLost = errors.New("collector work lease lost")

type Clock interface {
	Now() time.Time
}

type Heartbeat struct {
	CollectorID  domain.CollectorID
	ProtocolMin  int
	ProtocolMax  int
	Version      string
	BuildCommit  string
	Capabilities []Capability
	CommandPacks []CommandPack
	SourceHealth []SourceHealth
}

type Capability struct {
	Name    string
	Version string
}

type CommandPack struct {
	PackID       string
	Version      string
	DigestSHA256 string
}

type SourceHealth struct {
	SourceID     domain.SourceID
	Availability string
	SafeMessage  string
	CheckedAt    time.Time
}

type ClaimRequest struct {
	CollectorID domain.CollectorID
	Wait        time.Duration
	SourceIDs   []domain.SourceID
}

type LeaseRef struct {
	WorkID     domain.WorkID
	Attempt    int
	LeaseToken string
}

type ResultChunk struct {
	LeaseRef
	Index   int
	Payload []byte
	SHA256  string
}

type Finalization struct {
	LeaseRef
	RunID      domain.RunID
	Status     domain.ResultStatus
	ChunkCount int
	Bytes      int64
	SHA256     string
}

// ControlClient is the collector-owned port for the outbound control protocol.
type ControlClient interface {
	Heartbeat(context.Context, Heartbeat) error
	Claim(context.Context, ClaimRequest) (*domain.WorkLease, error)
	Start(context.Context, LeaseRef) error
	Renew(context.Context, LeaseRef) (time.Time, error)
	UploadChunk(context.Context, ResultChunk) error
	Finalize(context.Context, Finalization) error
}

type RuntimeConfig struct {
	CollectorID       domain.CollectorID
	SourceID          domain.SourceID
	Version           string
	BuildCommit       string
	Capabilities      []string
	HeartbeatInterval time.Duration
	ClaimWait         time.Duration
	RenewInterval     time.Duration
	BackoffMinimum    time.Duration
	BackoffMaximum    time.Duration
	ExecutionRetries  int
	ExecutionBackoff  time.Duration
	// AdditionalCapabilities are reviewed non-collection capabilities (for
	// example the credential access test) advertised alongside collection
	// operations. Advertising any of them also reports protocol support 1..2.
	AdditionalCapabilities []string
}

type Runtime struct {
	cfg           RuntimeConfig
	client        ControlClient
	executor      application.CollectionExecutor
	journal       *Journal
	clock         Clock
	sourceHealth  SourceHealth
	typedExecutor *application.TypedCollectionRegistry
	typedClient   TypedControlClient
}

func NewRuntime(cfg RuntimeConfig, client ControlClient, executor application.CollectionExecutor, journal *Journal, clock Clock) (*Runtime, error) {
	return NewRuntimeWithTyped(cfg, client, executor, nil, journal, clock)
}

func NewRuntimeWithTyped(cfg RuntimeConfig, client ControlClient, executor application.CollectionExecutor, typed *application.TypedCollectionRegistry, journal *Journal, clock Clock) (*Runtime, error) {
	if cfg.CollectorID == "" || cfg.SourceID == "" || cfg.Version == "" || client == nil || journal == nil || clock == nil || (typed == nil && (len(cfg.Capabilities) == 0 || executor == nil)) || (len(cfg.Capabilities) > 0 && executor == nil) {
		return nil, fmt.Errorf("collector runtime configuration and dependencies are required")
	}
	typedClient, supportsTyped := client.(TypedControlClient)
	if typed != nil && !supportsTyped {
		return nil, fmt.Errorf("typed collection client is required")
	}
	if cfg.HeartbeatInterval <= 0 || cfg.ClaimWait <= 0 || cfg.ClaimWait > cfg.HeartbeatInterval || cfg.RenewInterval <= 0 || cfg.BackoffMinimum <= 0 || cfg.BackoffMaximum < cfg.BackoffMinimum {
		return nil, fmt.Errorf("collector runtime timing configuration is invalid")
	}
	if cfg.ExecutionRetries < 0 || cfg.ExecutionRetries > 2 || (cfg.ExecutionRetries > 0 && cfg.ExecutionBackoff <= 0) {
		return nil, fmt.Errorf("collector execution retry configuration is invalid")
	}
	return &Runtime{
		cfg: cfg, client: client, executor: executor, journal: journal, clock: clock, typedExecutor: typed, typedClient: typedClient,
		sourceHealth: SourceHealth{SourceID: cfg.SourceID, Availability: "UNKNOWN", CheckedAt: clock.Now().UTC()},
	}, nil
}

func (r *Runtime) Run(ctx context.Context) error {
	nextHeartbeat := time.Time{}
	backoff := r.cfg.BackoffMinimum
	claimTyped := r.typedExecutor != nil
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !r.clock.Now().Before(nextHeartbeat) {
			capabilities := make([]Capability, 0, len(r.cfg.Capabilities))
			for _, name := range r.cfg.Capabilities {
				capabilities = append(capabilities, Capability{Name: name, Version: "1"})
			}
			heartbeat := Heartbeat{
				CollectorID: r.cfg.CollectorID, Version: r.cfg.Version, BuildCommit: r.cfg.BuildCommit,
				Capabilities: capabilities,
			}
			if r.executor != nil {
				heartbeat.SourceHealth = []SourceHealth{r.sourceHealth}
			}
			if r.typedExecutor != nil {
				heartbeat.ProtocolMin, heartbeat.ProtocolMax = 1, domain.CollectionProtocolVersion
				for _, id := range r.typedExecutor.Operations() {
					heartbeat.Capabilities = append(heartbeat.Capabilities, Capability{Name: string(id), Version: "1"})
				}
			}
			if len(r.cfg.AdditionalCapabilities) > 0 {
				heartbeat.ProtocolMin, heartbeat.ProtocolMax = 1, domain.CollectionProtocolVersion
				for _, name := range r.cfg.AdditionalCapabilities {
					heartbeat.Capabilities = append(heartbeat.Capabilities, Capability{Name: name, Version: "1"})
				}
			}
			err := r.client.Heartbeat(ctx, heartbeat)
			if err != nil {
				if err := wait(ctx, backoff); err != nil {
					return err
				}
				backoff = doubled(backoff, r.cfg.BackoffMaximum)
				continue
			}
			nextHeartbeat = r.clock.Now().Add(r.cfg.HeartbeatInterval)
			backoff = r.cfg.BackoffMinimum
		}
		pending, ok, err := r.journal.pending()
		if err != nil {
			// Claiming new work while pending state is unreadable could strand an
			// unacknowledged result, so treat it like any other operation failure.
			if err := wait(ctx, backoff); err != nil {
				return err
			}
			backoff = doubled(backoff, r.cfg.BackoffMaximum)
			continue
		}
		if ok {
			if pending.TypedPlan != nil {
				err = r.processTyped(ctx, pendingTypedLease(r.cfg.CollectorID, pending))
				if err != nil {
					if errors.Is(err, ErrLeaseLost) {
						err = r.journal.discardLease(pending.RunID)
					}
					if err != nil {
						if err := wait(ctx, backoff); err != nil {
							return err
						}
						backoff = doubled(backoff, r.cfg.BackoffMaximum)
					}
				}
				continue
			}
			lease := pendingLease(r.cfg.CollectorID, pending)
			if err := r.process(ctx, lease); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if errors.Is(err, ErrLeaseLost) {
					if discardErr := r.journal.discardLease(pending.RunID); discardErr != nil {
						return discardErr
					}
				} else {
					if err := wait(ctx, backoff); err != nil {
						return err
					}
					backoff = doubled(backoff, r.cfg.BackoffMaximum)
					continue
				}
			}
			backoff = r.cfg.BackoffMinimum
			continue
		}
		if claimTyped {
			claimTyped = r.executor == nil
			typedWait := r.cfg.ClaimWait
			if r.executor != nil {
				// A mixed collector also serves short-interval v1 work. Do not
				// hold its single claim loop in an empty typed long poll.
				typedWait = 0
			}
			lease, err := r.typedClient.ClaimTyped(ctx, ClaimRequest{CollectorID: r.cfg.CollectorID, Wait: typedWait, SourceIDs: r.typedExecutor.SourceIDs()})
			if err == nil && lease != nil {
				err = r.processTyped(ctx, *lease)
				if errors.Is(err, ErrLeaseLost) {
					err = r.journal.discardLease(lease.Plan.RunID)
				}
			}
			if err != nil {
				if err := wait(ctx, backoff); err != nil {
					return err
				}
				backoff = doubled(backoff, r.cfg.BackoffMaximum)
			} else {
				backoff = r.cfg.BackoffMinimum
			}
			continue
		}
		claimTyped = r.typedExecutor != nil
		lease, err := r.client.Claim(ctx, ClaimRequest{CollectorID: r.cfg.CollectorID, Wait: r.cfg.ClaimWait})
		if err != nil {
			if err := wait(ctx, backoff); err != nil {
				return err
			}
			backoff = doubled(backoff, r.cfg.BackoffMaximum)
			continue
		}
		backoff = r.cfg.BackoffMinimum
		if lease == nil {
			// An empty long-poll response is a successful control-plane exchange,
			// not a reconnect failure. Claim again immediately; bounded backoff is
			// reserved for transport and operation errors.
			continue
		}
		if err := r.process(ctx, *lease); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, ErrLeaseLost) {
				if discardErr := r.journal.discardLease(lease.Work.Task.RunID); discardErr != nil {
					return discardErr
				}
				continue
			}
			if err := wait(ctx, backoff); err != nil {
				return err
			}
			backoff = doubled(backoff, r.cfg.BackoffMaximum)
		}
	}
}

func (r *Runtime) process(ctx context.Context, lease domain.WorkLease) error {
	if lease.CollectorID != r.cfg.CollectorID || lease.Attempt < 1 || lease.LeaseToken == "" {
		return fmt.Errorf("claimed lease identity is invalid")
	}
	// A v1 executor owns one locally configured source instance. Never relabel
	// that instance's measurements using a same-cluster source from a lease.
	if lease.Work.Task.SourceID != r.cfg.SourceID {
		return fmt.Errorf("claimed work source is not locally configured")
	}
	if err := domain.ValidateCollectorWork(lease.Work); err != nil {
		return fmt.Errorf("validate claimed work: %w", err)
	}
	entry, existed, err := r.journal.begin(lease)
	if err != nil {
		return err
	}
	if entry.Result != nil {
		r.sourceHealth = sourceHealthFromResult(r.cfg.SourceID, *entry.Result)
		return r.deliver(ctx, lease, *entry.Result)
	}
	if existed && entry.State == journalStarted {
		result := interruptedResult(lease.Work.Task, r.clock.Now())
		if err := r.journal.storeResult(lease.Work.Task.RunID, result); err != nil {
			return err
		}
		return r.deliver(ctx, lease, result)
	}
	ref := leaseReference(lease)
	if err := r.client.Start(ctx, ref); err != nil {
		return fmt.Errorf("acknowledge collector work start: %w", err)
	}
	if err := r.journal.markStarted(lease.Work.Task.RunID); err != nil {
		return err
	}
	executionContext, cancel := context.WithCancel(ctx)
	renewalDone := make(chan error, 1)
	go r.renew(executionContext, cancel, ref, renewalDone)
	result := r.executeWithRetries(executionContext, lease.Work.Task)
	cancel()
	renewalErr := <-renewalDone
	result = boundedResult(lease, result, r.clock.Now())
	if err := r.journal.storeResult(lease.Work.Task.RunID, result); err != nil {
		return err
	}
	r.sourceHealth = sourceHealthFromResult(r.cfg.SourceID, result)
	if renewalErr != nil {
		return renewalErr
	}
	return r.deliver(ctx, lease, result)
}

func sourceHealthFromResult(sourceID domain.SourceID, result domain.CollectionResult) SourceHealth {
	health := SourceHealth{SourceID: sourceID, Availability: "AVAILABLE", CheckedAt: result.CompletedAt.UTC()}
	for _, failure := range result.Failures {
		switch failure.Code {
		case domain.FailureSourceUnavailable, domain.FailureDeadlineExceeded, domain.FailureUnauthorized:
			health.Availability = "UNAVAILABLE"
			health.SafeMessage = "last collection could not reach the configured source"
			return health
		}
	}
	return health
}

func (r *Runtime) executeWithRetries(ctx context.Context, task domain.CollectionTask) domain.CollectionResult {
	var result domain.CollectionResult
	for attempt := 0; attempt <= r.cfg.ExecutionRetries; attempt++ {
		result = r.executor.Execute(ctx, task)
		if !retryableCollectionResult(result) || attempt == r.cfg.ExecutionRetries {
			return result
		}
		if err := wait(ctx, r.cfg.ExecutionBackoff*time.Duration(attempt+1)); err != nil {
			return result
		}
	}
	return result
}

func retryableCollectionResult(result domain.CollectionResult) bool {
	if result.Status != domain.ResultFailed || len(result.Failures) == 0 {
		return false
	}
	for _, failure := range result.Failures {
		if !failure.Retryable {
			return false
		}
	}
	return true
}

func (r *Runtime) renew(ctx context.Context, cancel context.CancelFunc, ref LeaseRef, done chan<- error) {
	ticker := time.NewTicker(r.cfg.RenewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			done <- nil
			return
		case <-ticker.C:
			if _, err := r.client.Renew(ctx, ref); err != nil {
				cancel()
				done <- fmt.Errorf("renew collector work lease: %w", err)
				return
			}
		}
	}
}

func (r *Runtime) deliver(ctx context.Context, lease domain.WorkLease, result domain.CollectionResult) error {
	document := domain.NormalizeCollectorResultTimes(domain.CollectorResultDocument{
		SchemaVersion: domain.CollectorResultSchemaVersion, WorkID: lease.Work.WorkID, Attempt: lease.Attempt, Result: result,
	})
	encoded, err := domain.EncodeCollectorResult(document)
	if err != nil {
		return err
	}
	if int64(len(encoded)) > lease.Work.Task.MaxBytes || (len(encoded)+maxChunkBytes-1)/maxChunkBytes > maxChunks {
		return fmt.Errorf("canonical collector result exceeds assigned upload limit")
	}
	ref := leaseReference(lease)
	chunkCount := (len(encoded) + maxChunkBytes - 1) / maxChunkBytes
	for index := 0; index < chunkCount; index++ {
		start := index * maxChunkBytes
		end := min(start+maxChunkBytes, len(encoded))
		payload := encoded[start:end]
		digest := sha256.Sum256(payload)
		if err := r.client.UploadChunk(ctx, ResultChunk{LeaseRef: ref, Index: index, Payload: payload, SHA256: hex.EncodeToString(digest[:])}); err != nil {
			return fmt.Errorf("upload collector result chunk %d: %w", index, err)
		}
	}
	digest := sha256.Sum256(encoded)
	if err := r.client.Finalize(ctx, Finalization{
		LeaseRef: ref, RunID: result.Task.RunID, Status: result.Status, ChunkCount: chunkCount,
		Bytes: int64(len(encoded)), SHA256: hex.EncodeToString(digest[:]),
	}); err != nil {
		return fmt.Errorf("finalize collector result: %w", err)
	}
	return r.journal.markFinalized(result.Task.RunID)
}

func boundedResult(lease domain.WorkLease, result domain.CollectionResult, now time.Time) domain.CollectionResult {
	document := domain.NormalizeCollectorResultTimes(domain.CollectorResultDocument{
		SchemaVersion: domain.CollectorResultSchemaVersion, WorkID: lease.Work.WorkID, Attempt: lease.Attempt, Result: result,
	})
	encoded, err := domain.EncodeCollectorResult(document)
	validationErr := domain.ValidateCollectorResult(document, lease.Work, lease.Attempt)
	if err == nil && validationErr == nil && int64(len(encoded)) <= lease.Work.Task.MaxBytes && (len(encoded)+maxChunkBytes-1)/maxChunkBytes <= maxChunks {
		return document.Result
	}
	failureCode := domain.FailureInternal
	failureMessage := "collector result failed local validation"
	if err == nil && validationErr == nil {
		failureCode = domain.FailureResultLimit
		failureMessage = "collector result exceeds assigned upload limit"
	}
	completed := now.UTC()
	started := result.StartedAt.UTC()
	if started.IsZero() || completed.Before(started) {
		started = completed
	}
	bytesRead := result.Coverage.BytesRead
	if bytesRead < 0 {
		bytesRead = 0
	}
	if bytesRead > lease.Work.Task.MaxBytes {
		bytesRead = lease.Work.Task.MaxBytes
	}
	return domain.CollectionResult{
		Task: lease.Work.Task, Status: domain.ResultFailed, StartedAt: started, CompletedAt: completed,
		Coverage: domain.Coverage{BytesRead: bytesRead, Complete: false},
		Failures: []domain.CollectionFailure{{Code: failureCode, Message: failureMessage}},
	}
}

func interruptedResult(task domain.CollectionTask, now time.Time) domain.CollectionResult {
	timestamp := now.UTC()
	return domain.CollectionResult{
		Task: task, Status: domain.ResultFailed, StartedAt: timestamp, CompletedAt: timestamp,
		Coverage: domain.Coverage{Complete: false},
		Failures: []domain.CollectionFailure{{Code: domain.FailureInternal, Message: "collector restarted after execution began; result unavailable"}},
	}
}

func leaseReference(lease domain.WorkLease) LeaseRef {
	return LeaseRef{WorkID: lease.Work.WorkID, Attempt: lease.Attempt, LeaseToken: lease.LeaseToken}
}

func pendingLease(collectorID domain.CollectorID, entry journalEntry) domain.WorkLease {
	return domain.WorkLease{
		CollectorID: collectorID, Attempt: entry.Attempt, LeaseToken: entry.LeaseToken,
		Work: domain.CollectorWork{
			WorkID: entry.WorkID, Task: entry.Task, Status: domain.WorkLeased,
			AvailableAt: entry.Task.ScheduledFor, WorkExpiresAt: entry.Task.Deadline,
		},
	}
}

func doubled(value, maximum time.Duration) time.Duration {
	if value >= maximum/2 {
		return maximum
	}
	return value * 2
}

func wait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
