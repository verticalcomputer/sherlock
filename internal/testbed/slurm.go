package testbed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/alertdelivery"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	"github.com/verticalcomputer/sherlock/internal/slurmfailures"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

const slurmContract = `{"version":"sherlock.testbed.slurm/v1","threshold":3,"window_seconds":1800,"controls":["distinct_attempts","same_attempt_repeated","cancellations_preemption","conflicting_outcomes","reused_job_id"],"crashes":["slurm_incident_committed","slurm_delivery_claimed","slurm_receiver_accepted"],"transport":"simulated_http_receiver","acceptances_after_lost_receipt":2}`

var slurmCrashBoundaries = []string{"slurm_incident_committed", "slurm_delivery_claimed", "slurm_receiver_accepted"}

type SlurmFailureCase struct {
	ID        string `json:"id"`
	Passed    bool   `json:"passed"`
	Incidents int    `json:"incidents"`
	Alerts    int    `json:"alerts"`
}
type SlurmFailureReport struct {
	ReceiverMode        string             `json:"receiver_mode"`
	SourceMode          string             `json:"source_mode"`
	ContractSHA256      string             `json:"contract_sha256"`
	Passed              bool               `json:"passed"`
	Mode                string             `json:"mode"`
	Cases               []SlurmFailureCase `json:"cases"`
	CrashPIDs           []int              `json:"crash_pids"`
	FinalPID            int                `json:"final_pid"`
	Incidents           int                `json:"incidents"`
	Alerts              int                `json:"alerts"`
	ConsumedAttempts    int                `json:"consumed_attempts"`
	DeliveryClaims      int                `json:"delivery_claims"`
	DeliveryReceipts    int                `json:"delivery_receipts"`
	ReceiverAcceptances int                `json:"receiver_acceptances"`
	Violations          []string           `json:"violations"`
}

func slurmSetup(ctx context.Context, pool *pgxpool.Pool) error {
	if err := Setup(ctx, pool); err != nil {
		return err
	}
	_, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS testbed_slurm_receiver(prefix text NOT NULL,message text NOT NULL,accepted_at timestamptz NOT NULL DEFAULT clock_timestamp()); CREATE TABLE IF NOT EXISTS testbed_slurm_workers(prefix text NOT NULL,boundary text NOT NULL,process_id bigint NOT NULL,PRIMARY KEY(prefix,boundary));`)
	return err
}
func slurmPolicy(prefix string) slurmfailures.Policy {
	return slurmfailures.Policy{ID: prefix + "-policy", ClusterID: domain.ClusterID(prefix), SourceID: domain.SourceID(prefix + "-source"), SchedulerNamespace: "slurm", Threshold: 3, WindowSeconds: 1800, FreshForSeconds: 300}
}
func slurmPrepare(ctx context.Context, pool *pgxpool.Pool, kind string) (string, error) {
	suffix, err := (platform.RandomIDGenerator{}).NewID()
	if err != nil {
		return "", err
	}
	prefix := "tb-slurm-" + suffix
	if err = slurmFixtureSource(ctx, pool, prefix); err != nil {
		return "", err
	}
	var at time.Time
	if err = pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return "", err
	}
	at = at.UTC()
	records := []domain.SlurmJobLifecycle{}
	switch kind {
	case "same_attempt_repeated":
		records = append(records, slurmLifecycle(prefix, "42", 0, "FAILED", at))
	case "cancellations_preemption":
		for i, state := range []string{"CANCELLED", "PREEMPTED", "FAILED"} {
			records = append(records, slurmLifecycle(prefix, "42", i, state, at))
		}
	case "conflicting_outcomes":
		for i := 0; i < 3; i++ {
			records = append(records, slurmLifecycle(prefix, "42", i, "FAILED", at))
		}
		records = append(records, slurmLifecycle(prefix, "42", 0, "CANCELLED", at))
	case "reused_job_id":
		for i := 0; i < 3; i++ {
			l := slurmLifecycle(prefix, "42", 0, "FAILED", at)
			l.Job.SubmitAt = l.Job.SubmitAt.Add(-time.Duration(i) * time.Hour)
			l.RecordIdentity = domain.CanonicalSlurmLifecycleRecordID(l)
			records = append(records, l)
		}
	default:
		for i := 0; i < 3; i++ {
			records = append(records, slurmLifecycle(prefix, "42", i, "FAILED", at))
		}
	}
	if err = submitSlurmFixture(ctx, pool, prefix, prefix+"-first", records); err != nil {
		return "", err
	}
	// Repeated polling uses a distinct finalized collection run, with the same
	// canonical job attempts. This is separate from transport receipt replay.
	if err = submitSlurmFixture(ctx, pool, prefix, prefix+"-repeat", records); err != nil {
		return "", err
	}
	if _, err = storepg.NewSlurmFailureStore(pool).Enroll(ctx, slurmPolicy(prefix), 0, "testbed"); err != nil {
		return "", err
	}
	return prefix, nil
}

// The real Sender builds and validates the Slack HTTP request. This transport
// is a durable simulated receiver, with no external network access or secrets.
type slurmReceiver struct {
	pool   *pgxpool.Pool
	prefix string
	reject bool
}

func (s slurmReceiver) RoundTrip(r *http.Request) (*http.Response, error) {
	var body struct {
		Text string `json:"text"`
	}
	if r.Method != "POST" || r.URL.Host != "hooks.slack.com" {
		return nil, fmt.Errorf("unexpected simulated receiver request")
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		return nil, err
	}
	if !strings.Contains(body.Text, "incident-slurm-") || !strings.Contains(body.Text, "distinct_attempts=3") {
		return nil, fmt.Errorf("unexpected Slurm notification body")
	}
	if s.reject {
		return &http.Response{StatusCode: 503, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("retry"))}, nil
	}
	if _, err := s.pool.Exec(r.Context(), `INSERT INTO testbed_slurm_receiver(prefix,message) VALUES($1,$2)`, s.prefix, body.Text); err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
}
func sendSlurmFixture(ctx context.Context, pool *pgxpool.Pool, prefix string, claim storepg.AlertClaim, reject bool) alertdelivery.Result {
	sender := alertdelivery.Sender{Client: &http.Client{Transport: slurmReceiver{pool, prefix, reject}}}
	return sender.Send(ctx, "https://hooks.slack.com/services/SYNTHETIC/TEST/NO_SECRET", claim.Message)
}
func SlurmWorker(ctx context.Context, pool *pgxpool.Pool, prefix, boundary string, crash func() error) error {
	if !strings.HasPrefix(prefix, "tb-slurm-") {
		return fmt.Errorf("invalid Slurm lab prefix")
	}
	valid := boundary == ""
	for _, b := range slurmCrashBoundaries {
		valid = valid || boundary == b
	}
	if !valid {
		return fmt.Errorf("invalid Slurm crash boundary")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO testbed_slurm_workers(prefix,boundary,process_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, prefix, boundary, os.Getpid()); err != nil {
		return err
	}
	store := storepg.NewSlurmFailureStore(pool)
	if err := store.Evaluate(ctx, domain.ClusterID(prefix), prefix+"-policy"); err != nil {
		return err
	}
	fault := pipelineFault{pool: pool, prefix: prefix, boundary: boundary, crash: crash}
	if err := fault.fire(ctx, "slurm_incident_committed"); err != nil {
		return err
	}
	outbox, _ := storepg.NewAlertOutboxStore(pool)
	claim, found, err := outbox.ClaimForCluster(ctx, prefix)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("slurm notification was not claimable")
	}
	if err = fault.fire(ctx, "slurm_delivery_claimed"); err != nil {
		return err
	}
	result := sendSlurmFixture(ctx, pool, prefix, claim, false)
	if result.Outcome != alertdelivery.Accepted {
		return fmt.Errorf("simulated Slurm notification was not accepted")
	}
	if err = fault.fire(ctx, "slurm_receiver_accepted"); err != nil {
		return err
	}
	_, err = outbox.Finish(ctx, claim, result)
	return err
}
func RunSlurm(ctx context.Context, pool *pgxpool.Pool, launch PipelineLauncher, processes bool) (SlurmFailureReport, error) {
	report := SlurmFailureReport{ContractSHA256: domain.ChecksumSHA256([]byte(slurmContract)).String(), Mode: "IN_PROCESS_RECONSTRUCTION", ReceiverMode: "SIMULATED_HTTP_TRANSPORT", SourceMode: "LEASED_TYPED_RESULT_FIXTURE", Violations: []string{}}
	if pool == nil || launch == nil {
		return report, fmt.Errorf("slurm lab database and launcher required")
	}
	if err := slurmSetup(ctx, pool); err != nil {
		return report, err
	}
	for _, kind := range []string{"distinct_attempts", "same_attempt_repeated", "cancellations_preemption", "conflicting_outcomes", "reused_job_id"} {
		prefix, err := slurmPrepare(ctx, pool, kind)
		if err != nil {
			return report, err
		}
		store := storepg.NewSlurmFailureStore(pool)
		for range 3 {
			if err = store.Evaluate(ctx, domain.ClusterID(prefix), prefix+"-policy"); err != nil {
				return report, err
			}
		}
		c := SlurmFailureCase{ID: kind}
		if err = pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM incidents WHERE cluster_id=$1),(SELECT count(*) FROM gp09_alert_outbox WHERE cluster_id=$1)`, prefix).Scan(&c.Incidents, &c.Alerts); err != nil {
			return report, err
		}
		expected := 0
		if kind == "distinct_attempts" || kind == "reused_job_id" {
			expected = 1
		}
		c.Passed = c.Incidents == expected && c.Alerts == expected
		report.Cases = append(report.Cases, c)
		if !c.Passed {
			report.Violations = append(report.Violations, "Slurm control failed: "+kind)
		}
	}
	prefix, err := slurmPrepare(ctx, pool, "recovery")
	if err != nil {
		return report, err
	}
	pids := map[int]bool{}
	for _, boundary := range slurmCrashBoundaries {
		if err = launch(ctx, prefix, boundary); err != nil {
			return report, err
		}
		var pid int
		if err = pool.QueryRow(ctx, `SELECT process_id FROM testbed_crashes WHERE prefix=$1 AND boundary=$2`, prefix, boundary).Scan(&pid); err != nil {
			return report, fmt.Errorf("slurm crash marker missing: %w", err)
		}
		report.CrashPIDs = append(report.CrashPIDs, pid)
		pids[pid] = true
		var status string
		var claims, receipts, accepted, incidents, episodes, consumed int
		if err = pool.QueryRow(ctx, `SELECT o.status,o.attempt_count,(SELECT count(*) FROM gp09_alert_delivery_attempts a WHERE a.alert_id=o.alert_id),(SELECT count(*) FROM testbed_slurm_receiver WHERE prefix=$1),(SELECT count(*) FROM incidents WHERE cluster_id=$1),(SELECT count(*) FROM slurm_failure_episodes WHERE policy_id=$2),(SELECT count(*) FROM slurm_failure_consumed WHERE policy_id=$2) FROM gp09_alert_outbox o WHERE o.cluster_id=$1`, prefix, prefix+"-policy").Scan(&status, &claims, &receipts, &accepted, &incidents, &episodes, &consumed); err != nil {
			return report, err
		}
		expectedClaims, expectedAccepted := 0, 0
		if boundary == "slurm_delivery_claimed" {
			expectedClaims = 1
		}
		if boundary == "slurm_receiver_accepted" {
			expectedClaims, expectedAccepted = 2, 1
		}
		if claims != expectedClaims || accepted != expectedAccepted || receipts != 0 || incidents != 1 || episodes != 1 || consumed != 3 || expectedClaims == 0 && status != "PENDING" || expectedClaims > 0 && status != "LEASED" {
			report.Violations = append(report.Violations, "unexpected Slurm crash state: "+boundary)
		}
		// Advance ONLY this disposable lab's lease clock; production uses real expiry.
		if _, err = pool.Exec(ctx, `UPDATE gp09_alert_outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE cluster_id=$1 AND status='LEASED'`, prefix); err != nil {
			return report, err
		}
	}
	if err = launch(ctx, prefix, ""); err != nil {
		return report, err
	}
	if err = pool.QueryRow(ctx, `SELECT process_id FROM testbed_slurm_workers WHERE prefix=$1 AND boundary=''`, prefix).Scan(&report.FinalPID); err != nil {
		return report, err
	}
	var deliveryStatus string
	if err = pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM incidents WHERE cluster_id=$1),(SELECT count(*) FROM gp09_alert_outbox WHERE cluster_id=$1),(SELECT count(*) FROM slurm_failure_consumed WHERE policy_id=$2),o.attempt_count,(SELECT count(*) FROM gp09_alert_delivery_attempts a WHERE a.alert_id=o.alert_id),(SELECT count(*) FROM testbed_slurm_receiver WHERE prefix=$1),o.status FROM gp09_alert_outbox o WHERE o.cluster_id=$1`, prefix, prefix+"-policy").Scan(&report.Incidents, &report.Alerts, &report.ConsumedAttempts, &report.DeliveryClaims, &report.DeliveryReceipts, &report.ReceiverAcceptances, &deliveryStatus); err != nil {
		return report, err
	}
	if report.Incidents != 1 || report.Alerts != 1 || report.ConsumedAttempts != 3 || report.DeliveryClaims != 3 || report.DeliveryReceipts != 1 || report.ReceiverAcceptances != 2 || deliveryStatus != "ACCEPTED" {
		report.Violations = append(report.Violations, "Slurm replay lost or duplicated incident/notification state")
	}
	if processes {
		report.Mode = "ABRUPT_PROCESS_EXIT"
		if len(pids) != 3 || pids[report.FinalPID] {
			report.Violations = append(report.Violations, "distinct Slurm replacement processes missing")
		}
	}
	report.Passed = len(report.Violations) == 0
	return report, nil
}
