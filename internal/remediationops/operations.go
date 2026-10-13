// Package remediationops exposes bounded, redacted operational M15 state.
// It deliberately has no identifiers, targets, evidence, credentials, or
// mutation methods, so its Prometheus labels remain finite.
package remediationops

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	clientprom "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const MaxBuckets = 64

type Bucket struct {
	Class string
	Count int64
}

type Snapshot struct {
	At                                                            time.Time
	RunStates, RequestStates, DecisionCodes, FenceStates          []Bucket
	ActiveSupervisorLeases, ActiveRequestLeases, ActiveWorkLeases int64
	ActiveReservations                                            int64
	PendingVerification, TerminalRuns, RepairEffects              int64
	EffectLatencySeconds                                          float64
	SchedulerImpactSeconds                                        float64
	SchedulerImpactKnown                                          bool
}

type Reader interface {
	RemediationOperations(context.Context, string, int) (Snapshot, error)
}

type Observer struct {
	reader                              Reader
	cluster                             string
	registry                            *clientprom.Registry
	mu                                  sync.Mutex
	fences                              *clientprom.GaugeVec
	states, requests, decisions         *clientprom.GaugeVec
	leases, progress, latency, failures *clientprom.GaugeVec
	iterations                          *clientprom.CounterVec
	iterationDuration                   *clientprom.HistogramVec
}

func New(reader Reader, cluster string, registry *clientprom.Registry) (*Observer, error) {
	if reader == nil || cluster == "" || registry == nil {
		return nil, errors.New("remediation operations reader, cluster, and registerer are required")
	}
	o := &Observer{reader: reader, cluster: cluster, registry: registry,
		fences:            clientprom.NewGaugeVec(clientprom.GaugeOpts{Name: "sherlock_remediation_authority_mismatches", Help: "Current active-request authority mismatches; not historical failure counts."}, []string{"kind"}),
		states:            clientprom.NewGaugeVec(clientprom.GaugeOpts{Name: "sherlock_remediation_runs", Help: "Bounded remediation runs by state."}, []string{"state"}),
		requests:          clientprom.NewGaugeVec(clientprom.GaugeOpts{Name: "sherlock_remediation_requests", Help: "Bounded repair collection requests by state."}, []string{"status"}),
		decisions:         clientprom.NewGaugeVec(clientprom.GaugeOpts{Name: "sherlock_remediation_decisions", Help: "Latest eligibility/refusal decisions by stable code."}, []string{"code"}),
		leases:            clientprom.NewGaugeVec(clientprom.GaugeOpts{Name: "sherlock_remediation_active_leases", Help: "Active remediation leases by bounded kind."}, []string{"kind"}),
		progress:          clientprom.NewGaugeVec(clientprom.GaugeOpts{Name: "sherlock_remediation_operation_count", Help: "Bounded remediation lifecycle counts."}, []string{"kind"}),
		latency:           clientprom.NewGaugeVec(clientprom.GaugeOpts{Name: "sherlock_remediation_latency_seconds", Help: "Mean completed remediation effect latency."}, []string{"kind"}),
		failures:          clientprom.NewGaugeVec(clientprom.GaugeOpts{Name: "sherlock_remediation_runtime_events", Help: "Runtime failure events by stable class."}, []string{"class"}),
		iterations:        clientprom.NewCounterVec(clientprom.CounterOpts{Name: "sherlock_remediation_iterations_total", Help: "Supervisor iterations by closed outcome."}, []string{"outcome"}),
		iterationDuration: clientprom.NewHistogramVec(clientprom.HistogramOpts{Name: "sherlock_remediation_iteration_duration_seconds", Help: "Supervisor iteration duration by closed outcome."}, []string{"outcome"}),
	}
	registry.MustRegister(o.fences, o.states, o.requests, o.decisions, o.leases, o.progress, o.latency, o.failures, o.iterations, o.iterationDuration)
	return o, nil
}

func (o *Observer) Handler() http.Handler {
	mux := http.NewServeMux()
	metrics := promhttp.HandlerFor(o.registry, promhttp.HandlerOpts{})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		if o.Refresh(r.Context()) != nil {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		metrics.ServeHTTP(w, r)
	})
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		if o.Refresh(r.Context()) != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func (o *Observer) Refresh(ctx context.Context) error {
	if !o.mu.TryLock() {
		return errors.New("remediation operations busy")
	}
	defer o.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	snapshot, err := o.reader.RemediationOperations(ctx, o.cluster, MaxBuckets)
	if err != nil {
		return err
	}
	o.fences.Reset()
	for _, b := range snapshot.FenceStates {
		switch b.Class {
		case "configuration_revision_mismatch", "schedule_revision_mismatch", "worker_lease_expired", "supervisor_lease_expired":
			o.fences.WithLabelValues(b.Class).Add(float64(b.Count))
		default:
			o.fences.WithLabelValues("other").Add(float64(b.Count))
		}
	}
	o.states.Reset()
	o.requests.Reset()
	o.decisions.Reset()
	for _, b := range snapshot.RunStates {
		o.states.WithLabelValues(runClass(b.Class)).Add(float64(b.Count))
	}
	for _, b := range snapshot.RequestStates {
		o.requests.WithLabelValues(requestClass(b.Class)).Add(float64(b.Count))
	}
	for _, b := range snapshot.DecisionCodes {
		o.decisions.WithLabelValues(decisionClass(b.Class)).Add(float64(b.Count))
	}
	o.leases.WithLabelValues("supervisor").Set(float64(snapshot.ActiveSupervisorLeases))
	o.leases.WithLabelValues("request").Set(float64(snapshot.ActiveRequestLeases))
	o.leases.WithLabelValues("work").Set(float64(snapshot.ActiveWorkLeases))
	o.progress.WithLabelValues("pending_verification").Set(float64(snapshot.PendingVerification))
	o.progress.WithLabelValues("active_reservations").Set(float64(snapshot.ActiveReservations))
	o.progress.WithLabelValues("terminal_runs").Set(float64(snapshot.TerminalRuns))
	o.progress.WithLabelValues("committed_effects").Set(float64(snapshot.RepairEffects))
	o.latency.WithLabelValues("effect_to_completion").Set(snapshot.EffectLatencySeconds)
	if snapshot.SchedulerImpactKnown {
		o.latency.WithLabelValues("scheduler_claim_impact").Set(snapshot.SchedulerImpactSeconds)
	}
	return nil
}

func runClass(v string) string {
	switch v {
	case "PROPOSED", "POLICY_CHECK", "PREFLIGHT", "READY", "CANARY_EXECUTING", "VERIFYING", "ROLLING_OUT", "SUCCEEDED", "POLICY_BLOCKED", "PREFLIGHT_FAILED", "ROLLING_BACK", "ROLLED_BACK", "ROLLBACK_FAILED", "CONTAINED", "FAILED", "CANCELLED", "EXPIRED":
		return v
	}
	return "UNKNOWN"
}
func requestClass(v string) string {
	switch v {
	case "REQUESTED", "CLAIMED", "COMPLETED", "CANCEL_REQUESTED", "CANCELLED", "CONTAINED":
		return v
	}
	return "UNKNOWN"
}
func decisionClass(v string) string {
	switch v {
	case "SCHEDULE_DISPATCH_GAP", "SCHEDULE_FACTS_UNKNOWN", "STREAM_DISABLED", "COLLECTION_ACTIVE", "SOURCE_UNAVAILABLE", "COLLECTOR_UNAVAILABLE", "INVENTORY_MISSING", "COVERAGE_INCOMPLETE", "COLLECTION_FAILED", "STREAM_FRESH", "NORMAL_SCHEDULER_DUE":
		return v
	}
	return "OTHER"
}

// RecordFailure implements remediationruntime's optional observer. Unknown
// strings are deliberately collapsed so untrusted errors cannot create labels.
func (o *Observer) RecordFailure(class string) {
	switch class {
	case "deadline", "cancelled", "lease_fence", "state_fence", "signature_authority", "authority_refused", "iteration_error", "lock_timeout":
		o.failures.WithLabelValues(class).Inc()
	default:
		o.failures.WithLabelValues("iteration_error").Inc()
	}
}

// RecordIteration implements remediationruntime's optional observer. The
// result class is closed by the runtime; duration has no labels.
func (o *Observer) RecordIteration(duration time.Duration, class string) {
	outcome := iterationClass(class)
	o.iterations.WithLabelValues(outcome).Inc()
	o.iterationDuration.WithLabelValues(outcome).Observe(duration.Seconds())
}
func iterationClass(v string) string {
	switch v {
	case "ok", "deadline", "cancelled", "lease_fence", "state_fence", "signature_authority", "authority_refused", "iteration_error", "lock_timeout":
		return v
	}
	return "iteration_error"
}
