package investigationapi

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// DiagnosticWorkQueue is the durable M5 queue: claim leases work with a token
// and an attempt number, and record commits one attempt idempotently.
type DiagnosticWorkQueue interface {
	Claim(ctx context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, leaseToken string, leaseFor time.Duration) (domain.DiagnosticWorkLease, bool, error)
	Record(ctx context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, workID domain.DiagnosticWorkID, attempt int, leaseToken string, result domain.DiagnosticAttemptResult) (domain.DiagnosticRun, bool, error)
}

// CollectorExecutionAuthority reports whether one collector may execute
// diagnostics at all. A collector authorized to poll metrics is not thereby
// authorized to run commands, so this is a separate decision from identity.
type CollectorExecutionAuthority interface {
	MayExecuteDiagnostics(context.Context, domain.ClusterID, domain.CollectorID) (bool, error)
}

// DiagnosticWorkTransport adapts the durable queue to the collector control
// protocol. PostgreSQL reconstructs and authenticates the lease for every
// result; no process-local state participates in that authorization decision.
type DiagnosticWorkTransport struct {
	queue     DiagnosticWorkQueue
	authority CollectorExecutionAuthority
}

func NewDiagnosticWorkTransport(queue DiagnosticWorkQueue, authority CollectorExecutionAuthority) (*DiagnosticWorkTransport, error) {
	if queue == nil || authority == nil {
		return nil, fmt.Errorf("diagnostic work queue and execution authority are required")
	}
	return &DiagnosticWorkTransport{queue: queue, authority: authority}, nil
}

func (transport *DiagnosticWorkTransport) ClaimDiagnosticWork(ctx context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, leaseToken string, leaseFor time.Duration) (domain.DiagnosticWorkLease, bool, error) {
	permitted, err := transport.authority.MayExecuteDiagnostics(ctx, clusterID, collectorID)
	if err != nil {
		return domain.DiagnosticWorkLease{}, false, err
	}
	if !permitted {
		return domain.DiagnosticWorkLease{}, false, collectorcontrol.ErrDiagnosticExecutionNotPermitted
	}
	lease, found, err := transport.queue.Claim(ctx, clusterID, collectorID, leaseToken, leaseFor)
	if err != nil || !found {
		return domain.DiagnosticWorkLease{}, false, err
	}
	if lease.Work.Run.Request().ClusterID != clusterID || lease.RunnerID != string(collectorID) {
		return domain.DiagnosticWorkLease{}, false, application.ErrDiagnosticLeaseInvalid
	}
	return lease, true, nil
}

func (transport *DiagnosticWorkTransport) RecordDiagnosticAttempt(ctx context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, workID domain.DiagnosticWorkID, attempt int, leaseToken string, result domain.DiagnosticAttemptResult) (domain.DiagnosticRunStatus, bool, error) {
	permitted, err := transport.authority.MayExecuteDiagnostics(ctx, clusterID, collectorID)
	if err != nil {
		return "", false, err
	}
	if !permitted {
		return "", false, collectorcontrol.ErrDiagnosticExecutionNotPermitted
	}
	if result.WorkID != workID || result.Attempt != attempt || result.RunnerID != string(collectorID) {
		return "", false, application.ErrDiagnosticLeaseInvalid
	}
	run, recorded, err := transport.queue.Record(ctx, clusterID, collectorID, workID, attempt, leaseToken, result)
	if err != nil {
		if errors.Is(err, application.ErrDiagnosticLeaseInvalid) {
			return "", false, errors.Join(application.ErrDiagnosticLeaseInvalid, collectorcontrol.ErrWorkLeaseInvalid)
		}
		if errors.Is(err, application.ErrDiagnosticConflict) {
			return "", false, errors.Join(application.ErrDiagnosticConflict, collectorcontrol.ErrResultConflict)
		}
		return "", false, err
	}
	return run.Status(), recorded, nil
}

var _ collectorcontrol.DiagnosticWorkOperations = (*DiagnosticWorkTransport)(nil)

// AllowedCollectors permits diagnostic execution for an explicit set of
// collector identities.
//
// This is the decision that carries the risk, so it is made once per collector
// by an operator and lives outside the database: nothing an investigation, a
// model, or an enrolled collector does can add an entry. An empty set is not a
// valid authority -- a control plane that permits nobody should not expose an
// execution surface at all, and refuses to configure one.
type AllowedCollectors struct {
	permitted map[domain.CollectorID]struct{}
}

func NewAllowedCollectors(collectorIDs []string) (*AllowedCollectors, error) {
	if len(collectorIDs) == 0 {
		return nil, fmt.Errorf("a diagnostic execution allow-list requires at least one collector")
	}
	permitted := make(map[domain.CollectorID]struct{}, len(collectorIDs))
	for _, collectorID := range collectorIDs {
		if collectorID == "" {
			return nil, fmt.Errorf("a diagnostic execution allow-list may not contain an empty collector identity")
		}
		permitted[domain.CollectorID(collectorID)] = struct{}{}
	}
	return &AllowedCollectors{permitted: permitted}, nil
}

func (allowed *AllowedCollectors) MayExecuteDiagnostics(_ context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID) (bool, error) {
	if allowed == nil || clusterID == "" || collectorID == "" {
		return false, nil
	}
	_, permitted := allowed.permitted[collectorID]
	return permitted, nil
}
