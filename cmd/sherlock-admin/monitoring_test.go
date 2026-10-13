package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/monitoring"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func monitoringPolicyFixture() monitoring.Policy {
	return monitoring.Policy{ID: "gpu-temperature-fixture", ClusterID: "fixture-cluster", SourceID: "fixture-source", EntityKey: "fixture-cluster/GPU/node-1/GPU-a/",
		Rule: monitoring.RuleGPUThermal, RuleVersion: 1, Metric: "DCGM_FI_DEV_GPU_TEMP", Unit: "celsius", Binding: monitoring.Binding{Operation: "prometheus.gpu_temperature.v1", Scope: domain.CollectionScope{Nodes: []domain.StableNodeID{"node-1"}}, ScheduleRevision: 3, InventoryRevisionID: "expected-fixture-1"},
		StartupGraceSeconds: 60, FreshForSeconds: 60, ConfirmCount: 3, ConfirmWindowSeconds: 180, ConfirmMinDurationSeconds: 60, RecoverCount: 3, RecoverWindowSeconds: 180, RecoverMinDurationSeconds: 60, MaxSampleGapSeconds: 60, OpenThreshold: 85, RecoverBelow: 78, Severity: domain.HealthSeverityCritical}
}

func TestMonitoringCommandRequiresExactScopeFencesAndLocalActor(t *testing.T) {
	for _, fixture := range []struct {
		arguments []string
		action    string
	}{
		{[]string{"enroll", "--policy", "reviewed.json", "--expected-revision", "0", "--actor", "local-operator"}, "enroll"},
		{[]string{"disable", "--cluster", "fixture-cluster", "--policy-id", "policy-a", "--expected-revision", "3", "--actor", "local-operator"}, "disable"},
		{[]string{"status", "--cluster", "fixture cluster", "--policy-id", "policy ünicode"}, "status"},
		{[]string{"acknowledge", "--cluster", "fixture-cluster", "--policy-id", "policy-a", "--occurrence", "1", "--expected-episode-version", "2", "--actor", "local-operator"}, "acknowledge"},
		{[]string{"owner", "--cluster", "fixture-cluster", "--policy-id", "policy-a", "--occurrence", "1", "--expected-episode-version", "2", "--actor", "local-operator", "--clear-owner"}, "owner"},
		{[]string{"maintenance", "--cluster", "fixture-cluster", "--policy-id", "policy-a", "--occurrence", "1", "--expected-episode-version", "2", "--actor", "local-operator", "--maintenance-seconds", "86400"}, "maintenance"},
		{[]string{"review-recovery", "--cluster", "fixture-cluster", "--policy-id", "policy-a", "--occurrence", "1", "--expected-episode-version", "2", "--actor", "local-operator", "--evidence-id", "reviewed-evidence-a"}, "review-recovery"},
	} {
		command, err := parseMonitoringCommand(fixture.arguments)
		if err != nil || command.Action != fixture.action {
			t.Fatalf("%s command rejected: %v", fixture.action, err)
		}
	}
	base := []string{"acknowledge", "--cluster", "fixture-cluster", "--policy-id", "policy-a", "--occurrence", "1", "--expected-episode-version", "2", "--actor", "local-operator"}
	for _, arguments := range [][]string{
		{}, {"status"}, {"status", "--cluster", "fixture-cluster", "--policy-id", "policy-a", "--actor", "local-operator"},
		{"enroll", "--policy", "reviewed.json", "--actor", "local-operator"},
		{"disable", "--cluster", "fixture-cluster", "--policy-id", "policy-a", "--expected-revision", "0", "--actor", "local-operator"},
		append(append([]string{}, base...), "--cluster", "foreign-cluster"),
		append(append([]string{}, base...), "--actor=conflicting-actor"),
		append(append([]string{}, base...), "--policy-id", "*"),
		append(append([]string{}, base...), "extra"),
	} {
		if _, err := parseMonitoringCommand(arguments); err == nil {
			t.Fatalf("ambiguous/unfenced command accepted: %v", arguments)
		}
	}
}

func TestMonitoringMaintenanceAndOwnerChangesAreExplicitAndBounded(t *testing.T) {
	scope := []string{"--cluster", "fixture-cluster", "--policy-id", "policy-a", "--occurrence", "1", "--expected-episode-version", "2", "--actor", "local-operator"}
	for _, fixture := range []struct {
		action string
		flags  []string
		valid  bool
	}{
		{"maintenance", []string{"--maintenance-seconds", "1"}, true},
		{"maintenance", []string{"--clear-maintenance"}, true},
		{"maintenance", []string{}, false},
		{"maintenance", []string{"--maintenance-seconds", "0"}, false},
		{"maintenance", []string{"--maintenance-seconds", "86401"}, false},
		{"maintenance", []string{"--maintenance-seconds", "1", "--clear-maintenance"}, false},
		{"maintenance", []string{"--clear-maintenance=false"}, false},
		{"owner", []string{"--owner", "owner@example.invalid"}, true},
		{"owner", []string{"--clear-owner"}, true},
		{"owner", []string{}, false},
		{"owner", []string{"--owner", ""}, false},
		{"owner", []string{"--owner", "owner-a", "--clear-owner"}, false},
		{"owner", []string{"--owner", "bad\tactor"}, false},
		{"owner", []string{"--owner", strings.Repeat("a", 129)}, false},
	} {
		arguments := append([]string{fixture.action}, scope...)
		arguments = append(arguments, fixture.flags...)
		command, err := parseMonitoringCommand(arguments)
		if (err == nil) != fixture.valid {
			t.Fatalf("%s explicit change: %v", fixture.action, err)
		}
		if err == nil && fixture.action == "maintenance" && len(fixture.flags) == 1 && command.MaintenanceSeconds != 0 {
			t.Fatal("explicit clear changed into interval")
		}
	}
}

func TestMonitoringPolicyDecodeIsBoundedStrictAndServerStamped(t *testing.T) {
	policy := monitoringPolicyFixture()
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	decoded, err := decodeMonitoringPolicy(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Revision != 0 || !decoded.EnrolledAt.IsZero() {
		t.Fatal("CLI manufactured server authority")
	}
	mutate := func(change func(*monitoring.Policy)) []byte {
		p := policy
		change(&p)
		value, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	cases := map[string][]byte{
		"invalid-utf8":         []byte{'{', '"', 'i', 'd', '"', ':', '"', 0xff, '"', '}'},
		"nonobject":            []byte(`[]`),
		"nested-duplicate":     []byte(strings.Replace(string(data), `"scope":{"nodes"`, `"scope":{"nodes":[],"nodes"`, 1)),
		"oversize":             []byte(strings.Repeat(" ", monitoringPolicyLimit+1)),
		"trailing":             append(append([]byte{}, data...), []byte(" {}")...),
		"unknown-field":        append(append([]byte{}, data[:len(data)-1]...), []byte(`,"secret_marker":"DO_NOT_ECHO"}`)...),
		"duplicate-field":      append(append([]byte{}, data[:len(data)-1]...), []byte(`,"id":"conflicting"}`)...),
		"case-fold-duplicate":  append(append([]byte{}, data[:len(data)-1]...), []byte(`,"ID":"conflicting"}`)...),
		"unknown-rule":         mutate(func(p *monitoring.Policy) { p.RuleVersion = 999 }),
		"server-revision":      mutate(func(p *monitoring.Policy) { p.Revision = 1 }),
		"server-time":          mutate(func(p *monitoring.Policy) { p.EnrolledAt = at }),
		"empty-success":        mutate(func(p *monitoring.Policy) { p.AllowEmptySuccess = true }),
		"missing-authority":    mutate(func(p *monitoring.Policy) { p.Binding.InventoryRevisionID = "" }),
		"long-actor-reference": mutate(func(p *monitoring.Policy) { p.Binding.InventoryRevisionID = strings.Repeat("a", 129) }),
		"long-cluster":         mutate(func(p *monitoring.Policy) { p.ClusterID = domain.ClusterID(strings.Repeat("a", 129)) }),
		"wildcard-scope":       mutate(func(p *monitoring.Policy) { p.SourceID = "fixture-*" }),
		"long-id":              mutate(func(p *monitoring.Policy) { p.ID = strings.Repeat("a", 129) }),
		"missing-hold":         []byte(strings.Replace(string(data), `"confirm_min_duration_seconds":60,`, "", 1)),
		"null-hold":            []byte(strings.Replace(string(data), `"recover_min_duration_seconds":60`, `"recover_min_duration_seconds":null`, 1)),
		"negative-hold":        mutate(func(p *monitoring.Policy) { p.ConfirmMinDurationSeconds = -1 }),
		"invalid-gap":          mutate(func(p *monitoring.Policy) { p.MaxSampleGapSeconds = 0 }),
		"wrong-unit":           mutate(func(p *monitoring.Policy) { p.Unit = "watts" }),
		"unknown-scope-field":  []byte(strings.Replace(string(data), `"scope":{"nodes"`, `"scope":{"extra":true,"nodes"`, 1)),
	}
	zeroHold := policy
	zeroHold.ConfirmMinDurationSeconds, zeroHold.RecoverMinDurationSeconds = 0, 0
	zeroData, err := json.Marshal(zeroHold)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeMonitoringPolicy(bytes.NewReader(zeroData)); err != nil {
		t.Fatalf("explicit zero hold rejected: %v", err)
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeMonitoringPolicy(bytes.NewReader(input)); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}

func TestMonitoringInvalidPayloadDoesNotEchoSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid-policy.json")
	if err := os.WriteFile(path, []byte(`{"unknown":"never-echo-this-credential"}`), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	exit := runMonitoringAdmin([]string{"enroll", "--policy", path, "--expected-revision", "0", "--actor", "local-operator"}, &stdout, &stderr)
	if exit != 2 || stdout.Len() != 0 || strings.Contains(stderr.String(), "never-echo-this-credential") || strings.Contains(stderr.String(), path) {
		t.Fatalf("payload escaped safe error boundary: exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
}

type fakeMonitoringOperator struct {
	action                                 string
	cluster                                domain.ClusterID
	policyID, actor, owner, evidence       string
	occurrence, version, expected, seconds int64
	policy                                 monitoring.Policy
	err                                    error
}

func (f *fakeMonitoringOperator) Enroll(_ context.Context, p monitoring.Policy, r int64, a string) (storepg.MonitoringEnrollment, error) {
	f.action, f.policy, f.expected, f.actor = "enroll", p, r, a
	return storepg.MonitoringEnrollment{}, f.err
}
func (f *fakeMonitoringOperator) Disable(_ context.Context, c domain.ClusterID, p string, r int64, a string) (storepg.MonitoringEnrollment, error) {
	f.action, f.cluster, f.policyID, f.expected, f.actor = "disable", c, p, r, a
	return storepg.MonitoringEnrollment{}, f.err
}
func (f *fakeMonitoringOperator) Status(_ context.Context, c domain.ClusterID, p string) (storepg.MonitoringStatus, error) {
	f.action, f.cluster, f.policyID = "status", c, p
	return storepg.MonitoringStatus{}, f.err
}
func (f *fakeMonitoringOperator) Acknowledge(_ context.Context, c domain.ClusterID, p string, o, v int64, a string) (storepg.MonitoringEpisode, error) {
	f.capture("acknowledge", c, p, o, v, a)
	return storepg.MonitoringEpisode{}, f.err
}
func (f *fakeMonitoringOperator) AssignOwner(_ context.Context, c domain.ClusterID, p string, o, v int64, a, owner string) (storepg.MonitoringEpisode, error) {
	f.capture("owner", c, p, o, v, a)
	f.owner = owner
	return storepg.MonitoringEpisode{}, f.err
}
func (f *fakeMonitoringOperator) SetMaintenance(_ context.Context, c domain.ClusterID, p string, o, v int64, a string, seconds int64) (storepg.MonitoringEpisode, error) {
	f.capture("maintenance", c, p, o, v, a)
	f.seconds = seconds
	return storepg.MonitoringEpisode{}, f.err
}
func (f *fakeMonitoringOperator) ReviewRecovery(_ context.Context, c domain.ClusterID, p string, o, v int64, a, evidence string) (storepg.MonitoringEpisode, error) {
	f.capture("review-recovery", c, p, o, v, a)
	f.evidence = evidence
	return storepg.MonitoringEpisode{}, f.err
}
func (f *fakeMonitoringOperator) capture(action string, c domain.ClusterID, p string, o, v int64, a string) {
	f.action, f.cluster, f.policyID, f.occurrence, f.version, f.actor = action, c, p, o, v, a
}

func TestMonitoringDispatchPreservesEpisodeFenceAndDoesNotOutputFailedMutation(t *testing.T) {
	command := monitoringCommand{Action: "maintenance", ClusterID: "fixture-cluster", PolicyID: "policy-a", Occurrence: 3, ExpectedEpisodeVersion: 7, Actor: "local-operator", MaintenanceSeconds: 600}
	fake := &fakeMonitoringOperator{}
	var stdout bytes.Buffer
	if err := executeMonitoring(context.Background(), fake, command, &stdout); err != nil {
		t.Fatal(err)
	}
	if fake.action != "maintenance" || fake.cluster != "fixture-cluster" || fake.policyID != "policy-a" || fake.occurrence != 3 || fake.version != 7 || fake.actor != "local-operator" || fake.seconds != 600 {
		t.Fatalf("episode fence lost: %+v", fake)
	}
	stdout.Reset()
	fake.err = errors.New("database-secret-must-not-print")
	if err := executeMonitoring(context.Background(), fake, command, &stdout); err == nil || stdout.Len() != 0 {
		t.Fatal("failed mutation produced accepted output")
	}
}

func TestMonitoringDispatchKeepsIndependentEnrollmentAndEpisodeFences(t *testing.T) {
	for _, action := range []string{"enroll", "disable", "status", "acknowledge", "owner", "maintenance", "review-recovery"} {
		t.Run(action, func(t *testing.T) {
			command := monitoringCommand{Action: action, ClusterID: "fixture-cluster", PolicyID: "policy-a", ExpectedRevision: 9, Occurrence: 3, ExpectedEpisodeVersion: 7, Actor: "local-operator", Owner: "owner-a", MaintenanceSeconds: 0, EvidenceID: "evidence-a", Policy: monitoringPolicyFixture()}
			fake := &fakeMonitoringOperator{}
			var output bytes.Buffer
			if err := executeMonitoring(context.Background(), fake, command, &output); err != nil {
				t.Fatal(err)
			}
			if fake.action != action || !json.Valid(output.Bytes()) {
				t.Fatal("action or typed output changed")
			}
			switch action {
			case "enroll":
				if fake.expected != 9 || fake.policy.ID != command.Policy.ID || fake.policy.Revision != 0 || !fake.policy.EnrolledAt.IsZero() || fake.actor != command.Actor {
					t.Fatal("server-owned enrollment or control CAS changed")
				}
			case "disable":
				if fake.expected != 9 || fake.cluster != domain.ClusterID(command.ClusterID) || fake.policyID != command.PolicyID || fake.actor != command.Actor {
					t.Fatal("control CAS/scope changed")
				}
			case "status":
				if fake.cluster != domain.ClusterID(command.ClusterID) || fake.policyID != command.PolicyID {
					t.Fatal("status scope changed")
				}
			default:
				if fake.occurrence != 3 || fake.version != 7 || fake.actor != command.Actor || fake.cluster != domain.ClusterID(command.ClusterID) || fake.policyID != command.PolicyID {
					t.Fatal("episode CAS/scope changed")
				}
			}
			if action == "owner" && fake.owner != "owner-a" || action == "review-recovery" && fake.evidence != "evidence-a" || action == "maintenance" && fake.seconds != 0 {
				t.Fatal("explicit operation payload changed")
			}
		})
	}
}

func TestMonitoringEntrypointRejectsUnfencedInputBeforeDatabaseAccess(t *testing.T) {
	t.Setenv("SHERLOCK_DATABASE_URL", "not-a-valid-dsn-credential-marker")
	var stdout, stderr bytes.Buffer
	if exit := run([]string{"monitoring", "acknowledge", "--cluster", "fixture-cluster", "--policy-id", "policy-a"}, &stdout, &stderr); exit != 2 || stdout.Len() != 0 || stderr.String() != "invalid monitoring request\n" {
		t.Fatalf("unsafe dispatch output: exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
}
