// Package slurmfailures evaluates committed Slurm attempts without model input.
package slurmfailures

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const RuleID = "slurm.job_failures.v1"
const MaxRecords = 4096

type Policy struct {
	ID                 string                    `json:"id"`
	ClusterID          domain.ClusterID          `json:"cluster_id"`
	SourceID           domain.SourceID           `json:"source_id"`
	SchedulerNamespace domain.SchedulerNamespace `json:"scheduler_namespace"`
	NodeID             domain.StableNodeID       `json:"node_id,omitempty"`
	Threshold          int                       `json:"threshold"`
	WindowSeconds      int                       `json:"window_seconds"`
	FreshForSeconds    int                       `json:"fresh_for_seconds"`
}

func Token(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-:/", r)) {
			return false
		}
	}
	return true
}
func (p Policy) Validate() error {
	if !Token(p.ID) || !Token(string(p.ClusterID)) || !Token(string(p.SourceID)) || !Token(string(p.SchedulerNamespace)) || p.NodeID != "" && !Token(string(p.NodeID)) || p.Threshold < 2 || p.Threshold > 32 || p.WindowSeconds < 60 || p.WindowSeconds > 86400 || p.FreshForSeconds < 30 || p.FreshForSeconds > 3600 {
		return fmt.Errorf("invalid Slurm failure policy bounds")
	}
	return nil
}

// Class excludes operator cancellations and scheduler preemption. Unknown states
// never become healthy or failed by default; DEADLINE is intentionally excluded.
func Class(state string) string {
	fields := strings.Fields(strings.ToUpper(state))
	if len(fields) == 0 {
		return "OTHER"
	}
	switch strings.TrimSuffix(fields[0], "+") {
	case "FAILED", "NODE_FAIL", "OUT_OF_MEMORY", "BOOT_FAIL", "TIMEOUT":
		return "FAILURE"
	case "CANCELLED", "PREEMPTED", "COMPLETED", "DEADLINE":
		return "EXCLUDED"
	}
	return "OTHER"
}

type Record struct {
	Lifecycle domain.SlurmJobLifecycle `json:"lifecycle"`
	RunID     domain.RunID             `json:"run_id"`
}
type Attempt struct {
	Key      string             `json:"key"`
	Job      domain.JobIdentity `json:"job"`
	EndAt    time.Time          `json:"end_at"`
	RecordID string             `json:"record_id"`
	RunID    domain.RunID       `json:"run_id"`
}
type Evaluation struct {
	Failures            []Attempt `json:"failures"`
	ConflictingAttempts int       `json:"conflicting_attempts"`
	ExcludedAttempts    int       `json:"excluded_attempts"`
}

func Key(job domain.JobIdentity) string {
	job.SubmitAt = job.SubmitAt.UTC()
	raw, _ := json.Marshal(job)
	return domain.ChecksumSHA256(raw).String()
}
func Evaluate(p Policy, records []Record, now time.Time) (Evaluation, error) {
	out := Evaluation{Failures: []Attempt{}}
	if err := p.Validate(); err != nil {
		return out, err
	}
	if now.IsZero() || len(records) > MaxRecords {
		return out, fmt.Errorf("slurm failure input exceeds bounds")
	}
	type group struct {
		failure, excluded bool
		attempt           Attempt
	}
	groups := map[string]*group{}
	for _, r := range records {
		l := r.Lifecycle
		if l.ClusterID != p.ClusterID || l.SourceID != p.SourceID || l.Job.SchedulerNamespace != p.SchedulerNamespace {
			continue
		}
		if _, err := domain.CreateJobIdentity(l.Job); err != nil || l.SubmitQuality != domain.SlurmFieldPresent || l.RecordIdentity == "" || r.RunID == "" {
			continue
		}
		key := Key(l.Job)
		g := groups[key]
		if g == nil {
			g = &group{}
			groups[key] = g
		}
		if Class(l.RawState) == "EXCLUDED" {
			g.excluded = true
			continue
		}
		if Class(l.RawState) != "FAILURE" || l.EndQuality != domain.SlurmFieldPresent || l.EndAt.IsZero() || l.EndAt.Before(l.Job.SubmitAt) || l.EndAt.After(now) || !l.EndAt.After(now.Add(-time.Duration(p.WindowSeconds)*time.Second)) || p.NodeID != "" && !slices.Contains(l.NodeIDs, p.NodeID) {
			continue
		}
		g.failure = true
		// One stable, actual immutable record represents the attempt. Duplicate
		// CURRENT/accounting observations and repeated polls never increase counts.
		if g.attempt.Key == "" || l.RecordIdentity < g.attempt.RecordID {
			g.attempt = Attempt{Key: key, Job: l.Job, EndAt: l.EndAt, RecordID: l.RecordIdentity, RunID: r.RunID}
		}
	}
	for _, g := range groups {
		if g.excluded {
			out.ExcludedAttempts++
			if g.failure {
				out.ConflictingAttempts++
			}
			continue
		}
		if g.failure {
			out.Failures = append(out.Failures, g.attempt)
		}
	}
	slices.SortFunc(out.Failures, func(a, b Attempt) int {
		if c := a.EndAt.Compare(b.EndAt); c != 0 {
			return c
		}
		return strings.Compare(a.Key, b.Key)
	})
	return out, nil
}
