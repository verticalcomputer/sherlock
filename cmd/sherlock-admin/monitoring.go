package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/monitoring"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

const monitoringPolicyLimit = 64 * 1024

// Actor is local operator-supplied audit attribution. It is never a verified
// principal or an authorization credential; this command requires local DB access.
type monitoringCommand struct {
	Action, ClusterID, PolicyID, Actor, PolicyPath       string
	ExpectedRevision, Occurrence, ExpectedEpisodeVersion int64
	Owner, EvidenceID                                    string
	MaintenanceSeconds                                   int64
	Policy                                               monitoring.Policy
}

func parseMonitoringCommand(arguments []string) (monitoringCommand, error) {
	if len(arguments) == 0 {
		return monitoringCommand{}, errors.New("monitoring action required")
	}
	command := monitoringCommand{Action: arguments[0]}
	allowed := map[string]bool{}
	allow := func(names ...string) {
		for _, name := range names {
			allowed[name] = true
		}
	}
	switch command.Action {
	case "enroll":
		allow("policy", "expected-revision", "actor")
	case "disable":
		allow("cluster", "policy-id", "expected-revision", "actor")
	case "status":
		allow("cluster", "policy-id")
	case "acknowledge":
		allow("cluster", "policy-id", "occurrence", "expected-episode-version", "actor")
	case "owner":
		allow("cluster", "policy-id", "occurrence", "expected-episode-version", "actor", "owner", "clear-owner")
	case "maintenance":
		allow("cluster", "policy-id", "occurrence", "expected-episode-version", "actor", "maintenance-seconds", "clear-maintenance")
	case "review-recovery":
		allow("cluster", "policy-id", "occurrence", "expected-episode-version", "actor", "evidence-id")
	default:
		return monitoringCommand{}, errors.New("unknown monitoring action")
	}
	flags := flag.NewFlagSet("monitoring "+command.Action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&command.ClusterID, "cluster", "", "exact cluster identifier")
	flags.StringVar(&command.PolicyID, "policy-id", "", "exact policy identifier")
	flags.StringVar(&command.Actor, "actor", "", "operator-supplied local audit identity; not a verified principal")
	flags.StringVar(&command.PolicyPath, "policy", "", "reviewed policy JSON file")
	flags.Int64Var(&command.ExpectedRevision, "expected-revision", -1, "expected control revision; zero creates a new policy")
	flags.Int64Var(&command.Occurrence, "occurrence", 0, "exact episode occurrence")
	flags.Int64Var(&command.ExpectedEpisodeVersion, "expected-episode-version", 0, "expected episode version")
	flags.StringVar(&command.Owner, "owner", "", "local owner attribution")
	clearOwner := flags.Bool("clear-owner", false, "explicitly remove owner")
	flags.Int64Var(&command.MaintenanceSeconds, "maintenance-seconds", -1, "bounded suppression interval in seconds")
	clearMaintenance := flags.Bool("clear-maintenance", false, "explicitly clear suppression")
	flags.StringVar(&command.EvidenceID, "evidence-id", "", "reviewed recovery evidence identifier")
	if err := uniqueMonitoringFlags(arguments[1:], flags); err != nil {
		return monitoringCommand{}, errors.New("duplicate or invalid monitoring flags")
	}
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 {
		return monitoringCommand{}, errors.New("invalid monitoring flags")
	}
	invalid := false
	seen := map[string]bool{}
	flags.Visit(func(f *flag.Flag) {
		if !allowed[f.Name] || seen[f.Name] {
			invalid = true
		}
		seen[f.Name] = true
	})
	if invalid {
		return monitoringCommand{}, errors.New("flags do not match monitoring action")
	}
	if command.Action == "enroll" {
		if command.PolicyPath == "" || strings.IndexFunc(command.PolicyPath, unicode.IsControl) >= 0 || command.ExpectedRevision < 0 || !validMonitoringActor(command.Actor) {
			return monitoringCommand{}, errors.New("invalid monitoring enrollment scope")
		}
		return command, nil
	}
	if !validMonitoringIdentifier(command.ClusterID) || !validMonitoringIdentifier(command.PolicyID) {
		return monitoringCommand{}, errors.New("invalid monitoring scope")
	}
	if command.Action == "status" {
		return command, nil
	}
	if !validMonitoringActor(command.Actor) {
		return monitoringCommand{}, errors.New("invalid local operator attribution")
	}
	if command.Action == "disable" {
		if command.ExpectedRevision < 1 {
			return monitoringCommand{}, errors.New("expected control revision required")
		}
		return command, nil
	}
	if command.Occurrence < 1 || command.ExpectedEpisodeVersion < 1 {
		return monitoringCommand{}, errors.New("exact occurrence and episode version required")
	}
	switch command.Action {
	case "owner":
		if *clearOwner {
			if seen["owner"] {
				return monitoringCommand{}, errors.New("owner change is ambiguous")
			}
			command.Owner = ""
		} else if !validMonitoringActor(command.Owner) || seen["clear-owner"] {
			return monitoringCommand{}, errors.New("explicit owner change required")
		}
	case "maintenance":
		if *clearMaintenance {
			if seen["maintenance-seconds"] {
				return monitoringCommand{}, errors.New("maintenance change is ambiguous")
			}
			command.MaintenanceSeconds = 0
		} else if command.MaintenanceSeconds < 1 || command.MaintenanceSeconds > 86400 || seen["clear-maintenance"] {
			return monitoringCommand{}, errors.New("bounded explicit maintenance required")
		}
	case "review-recovery":
		if !validMonitoringIdentifier(command.EvidenceID) {
			return monitoringCommand{}, errors.New("reviewed evidence identifier required")
		}
	}
	return command, nil
}

func uniqueMonitoringFlags(arguments []string, flags *flag.FlagSet) error {
	seen := map[string]bool{}
	for index := 0; index < len(arguments); index++ {
		token := arguments[index]
		if !strings.HasPrefix(token, "-") || token == "-" || token == "--" {
			return errors.New("invalid monitoring flag")
		}
		name := strings.TrimPrefix(strings.TrimPrefix(token, "-"), "-")
		name, _, hasValue := strings.Cut(name, "=")
		definition := flags.Lookup(name)
		if definition == nil || seen[name] {
			return errors.New("duplicate or invalid monitoring flag")
		}
		seen[name] = true
		if hasValue {
			continue
		}
		if boolean, ok := definition.Value.(interface{ IsBoolFlag() bool }); ok && boolean.IsBoolFlag() {
			continue
		}
		index++
		if index >= len(arguments) {
			return errors.New("monitoring flag value missing")
		}
	}
	return nil
}

func validMonitoringActor(value string) bool {
	return value != "" && utf8.ValidString(value) && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "*?") && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validMonitoringIdentifier(value string) bool {
	return validMonitoringActor(value) && !strings.ContainsAny(value, "*?")
}

// Strictly bound before decoding. Neither decode nor validation errors are
// printed, so malformed input can never echo credentials or operational payloads.
func decodeMonitoringPolicy(reader io.Reader) (monitoring.Policy, error) {
	data, err := io.ReadAll(io.LimitReader(reader, monitoringPolicyLimit+1))
	if err != nil || len(data) == 0 || len(data) > monitoringPolicyLimit || !utf8.Valid(data) {
		return monitoring.Policy{}, errors.New("invalid bounded monitoring policy")
	}
	if err := uniqueMonitoringJSON(data); err != nil {
		return monitoring.Policy{}, errors.New("invalid monitoring policy JSON")
	}
	var declared map[string]json.RawMessage
	if json.Unmarshal(data, &declared) != nil {
		return monitoring.Policy{}, errors.New("invalid monitoring policy object")
	}
	for _, name := range []string{"confirm_min_duration_seconds", "recover_min_duration_seconds"} {
		value, present := declared[name]
		if !present || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return monitoring.Policy{}, errors.New("explicit monitoring hold durations required")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var policy monitoring.Policy
	if err := decoder.Decode(&policy); err != nil {
		return monitoring.Policy{}, errors.New("invalid monitoring policy JSON")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return monitoring.Policy{}, errors.New("trailing monitoring policy JSON")
	}
	if policy.Revision != 0 || !policy.EnrolledAt.IsZero() {
		return monitoring.Policy{}, errors.New("server-owned monitoring policy fields")
	}
	// Local validation establishes syntax only. The store stamps enrollment
	// revision/time and revalidates durable authority transactionally.
	if !validMonitoringIdentifier(policy.ID) || !validMonitoringIdentifier(string(policy.ClusterID)) || !validMonitoringIdentifier(string(policy.SourceID)) ||
		len(policy.EntityKey) > 256 || strings.ContainsAny(policy.EntityKey, "*?") ||
		(policy.Binding.InventoryRevisionID != "" && !validMonitoringIdentifier(policy.Binding.InventoryRevisionID)) {
		return monitoring.Policy{}, errors.New("invalid persisted monitoring scope")
	}
	for _, node := range policy.Binding.Scope.Nodes {
		if !validMonitoringIdentifier(string(node)) {
			return monitoring.Policy{}, errors.New("invalid persisted monitoring node scope")
		}
	}
	if monitoring.ValidateEnrollmentRequest(policy) != nil {
		return monitoring.Policy{}, errors.New("invalid monitoring policy contract")
	}
	return policy, nil
}

// encoding/json otherwise accepts duplicate keys. Reject them (including
// case-fold collisions) at every object level before typed decoding.
func uniqueMonitoringJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var read func(int) error
	read = func(depth int) error {
		if depth > 16 {
			return errors.New("JSON depth bound")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok {
					return errors.New("invalid JSON key")
				}
				name = strings.ToLower(name)
				if seen[name] {
					return errors.New("duplicate JSON key")
				}
				seen[name] = true
				if err := read(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := read(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		_, err = decoder.Token()
		return err
	}
	if err := read(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func runMonitoringAdmin(arguments []string, stdout, stderr io.Writer) int {
	command, err := parseMonitoringCommand(arguments)
	if err != nil {
		fmt.Fprintln(stderr, "invalid monitoring request")
		return 2
	}
	if command.Action == "enroll" {
		file, err := os.Open(command.PolicyPath)
		if err != nil {
			fmt.Fprintln(stderr, "invalid monitoring enrollment")
			return 2
		}
		command.Policy, err = decodeMonitoringPolicy(file)
		file.Close()
		if err != nil {
			fmt.Fprintln(stderr, "invalid monitoring enrollment")
			return 2
		}
	}
	cfg, err := config.LoadControlAdmin()
	if err != nil {
		fmt.Fprintln(stderr, "invalid admin configuration")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := administerMonitoring(ctx, cfg.DatabaseURL, command, stdout); err != nil {
		switch {
		case errors.Is(err, storepg.ErrMonitoringNotFound):
			fmt.Fprintln(stderr, "monitoring scope not found")
		case errors.Is(err, storepg.ErrMonitoringRevision):
			fmt.Fprintln(stderr, "monitoring revision changed; read current status")
		case errors.Is(err, storepg.ErrMonitoringAuthority):
			fmt.Fprintln(stderr, "monitoring authority is unavailable")
		case errors.Is(err, storepg.ErrMonitoringPolicyConflict):
			fmt.Fprintln(stderr, "policy semantics are immutable; disable and enroll a new policy identifier")
		default:
			fmt.Fprintln(stderr, "monitoring operation failed")
		}
		return 1
	}
	return 0
}

func administerMonitoring(ctx context.Context, databaseURL string, command monitoringCommand, stdout io.Writer) error {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	return executeMonitoring(ctx, storepg.NewMonitoringStore(pool), command, stdout)
}

type monitoringOperatorStore interface {
	Enroll(context.Context, monitoring.Policy, int64, string) (storepg.MonitoringEnrollment, error)
	Disable(context.Context, domain.ClusterID, string, int64, string) (storepg.MonitoringEnrollment, error)
	Status(context.Context, domain.ClusterID, string) (storepg.MonitoringStatus, error)
	Acknowledge(context.Context, domain.ClusterID, string, int64, int64, string) (storepg.MonitoringEpisode, error)
	AssignOwner(context.Context, domain.ClusterID, string, int64, int64, string, string) (storepg.MonitoringEpisode, error)
	SetMaintenance(context.Context, domain.ClusterID, string, int64, int64, string, int64) (storepg.MonitoringEpisode, error)
	ReviewRecovery(context.Context, domain.ClusterID, string, int64, int64, string, string) (storepg.MonitoringEpisode, error)
}

func executeMonitoring(ctx context.Context, store monitoringOperatorStore, command monitoringCommand, stdout io.Writer) error {
	cluster := domain.ClusterID(command.ClusterID)
	var result any
	var err error
	switch command.Action {
	case "enroll":
		result, err = store.Enroll(ctx, command.Policy, command.ExpectedRevision, command.Actor)
	case "disable":
		result, err = store.Disable(ctx, cluster, command.PolicyID, command.ExpectedRevision, command.Actor)
	case "status":
		result, err = store.Status(ctx, cluster, command.PolicyID)
	case "acknowledge":
		result, err = store.Acknowledge(ctx, cluster, command.PolicyID, command.Occurrence, command.ExpectedEpisodeVersion, command.Actor)
	case "owner":
		result, err = store.AssignOwner(ctx, cluster, command.PolicyID, command.Occurrence, command.ExpectedEpisodeVersion, command.Actor, command.Owner)
	case "maintenance":
		result, err = store.SetMaintenance(ctx, cluster, command.PolicyID, command.Occurrence, command.ExpectedEpisodeVersion, command.Actor, command.MaintenanceSeconds)
	case "review-recovery":
		result, err = store.ReviewRecovery(ctx, cluster, command.PolicyID, command.Occurrence, command.ExpectedEpisodeVersion, command.Actor, command.EvidenceID)
	default:
		return errors.New("invalid monitoring action")
	}
	if err != nil {
		return err
	}
	// DTOs contain only versioned policy/episode/audit facts. Never serialize a
	// database error, DSN, raw observation labels or source response bodies.
	return json.NewEncoder(stdout).Encode(result)
}
