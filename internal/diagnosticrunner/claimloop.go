package diagnosticrunner

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"time"
)

// ClaimLoopConfig bounds how often the head node returns to the control plane.
type ClaimLoopConfig struct {
	// IdleBackoff pauses after an empty claim. HeadNode's poll already blocks
	// for its configured wait, so this only keeps a control plane that answers
	// immediately from being polled in a tight loop.
	IdleBackoff time.Duration
	// FailureBackoffMinimum and FailureBackoffMaximum bound the exponential
	// backoff applied to consecutive failures.
	FailureBackoffMinimum time.Duration
	FailureBackoffMaximum time.Duration
}

// ClaimLoop drives HeadNode.RunOnce until its context ends.
//
// It is deliberately thin, because the interesting decisions are already made
// elsewhere: HeadNode records an execution failure as a failed attempt rather
// than dropping it, and returns an error only when claiming or recording left
// the queue's state uncertain. So the loop's whole job is pacing -- drain
// immediately while work exists, pause briefly when the queue is empty, and
// back off on the failures that mean the control plane is unreachable or
// refusing.
//
// It never exits on its own. A head node that stopped claiming would park every
// investigation that dispatched a diagnostic in AWAITING_EVIDENCE until its
// deadline, with nothing in the control plane able to tell that from a queue
// that is simply quiet.
type ClaimLoop struct {
	head   *HeadNode
	logger *slog.Logger
	config ClaimLoopConfig
	// sleep is replaced in tests so pacing is asserted without real time.
	sleep func(context.Context, time.Duration) error
	// jitter returns a value in [0,1). Retries spread so that several head
	// nodes recovering from one control-plane outage do not resynchronize.
	jitter func() float64
}

func NewClaimLoop(head *HeadNode, config ClaimLoopConfig, loggers ...*slog.Logger) (*ClaimLoop, error) {
	if head == nil {
		return nil, errors.New("diagnostic claim loop requires a head node")
	}
	if config.IdleBackoff <= 0 || config.FailureBackoffMinimum <= 0 || config.FailureBackoffMaximum < config.FailureBackoffMinimum {
		return nil, errors.New("diagnostic claim loop backoff configuration is invalid")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if len(loggers) > 0 && loggers[0] != nil {
		logger = loggers[0]
	}
	return &ClaimLoop{head: head, logger: logger, config: config, sleep: waitFor, jitter: rand.Float64}, nil
}

// Run claims and executes until the context ends, and returns its error.
func (loop *ClaimLoop) Run(ctx context.Context) error {
	if loop == nil {
		return errors.New("diagnostic claim loop is unavailable")
	}
	failures := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		claimed, err := loop.head.RunOnce(ctx)
		switch {
		case err != nil:
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			failures++
			// The error text stays on the head node's own stderr and never
			// becomes a durable record, so it may carry the host and transport
			// detail an operator needs to fix the thing.
			loop.logger.Warn("diagnostic.claim_cycle_failed", "consecutive_failures", failures, "claimed", claimed, "error", err.Error())
			if err := loop.sleep(ctx, loop.failureBackoff(failures)); err != nil {
				return err
			}
		case claimed:
			failures = 0
			loop.logger.Info("diagnostic.attempt_recorded", "runner_id", loop.head.config.RunnerID)
			// Claim again immediately: a queue holding work should drain.
		default:
			failures = 0
			if err := loop.sleep(ctx, loop.config.IdleBackoff); err != nil {
				return err
			}
		}
	}
}

// failureBackoff doubles per consecutive failure up to the configured ceiling,
// then spreads the result across the upper half of that delay.
func (loop *ClaimLoop) failureBackoff(failures int) time.Duration {
	delay := loop.config.FailureBackoffMinimum
	for range failures - 1 {
		if delay >= loop.config.FailureBackoffMaximum/2 {
			delay = loop.config.FailureBackoffMaximum
			break
		}
		delay *= 2
	}
	spread := time.Duration(float64(delay) * 0.5 * loop.jitter())
	return delay - spread
}

func waitFor(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
