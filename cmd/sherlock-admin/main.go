package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adminmanage"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `usage:
  sherlock-admin bootstrap <cluster-id>
  sherlock-admin revoke <collector-id>
  sherlock-admin api-key create --cluster <cluster-id> --label <safe-label> --expires-in <duration> --capability <capability> [--capability <capability> ...]
  sherlock-admin api-key list --cluster <cluster-id>
  sherlock-admin api-key revoke --cluster <cluster-id> --key-id <public-key-id>
  sherlock-admin credential-admin grant --cluster <cluster-id> --subject <access-subject> --actor <operator-subject>
  sherlock-admin credential-admin revoke --cluster <cluster-id> --subject <access-subject> --actor <operator-subject>
  sherlock-admin credential-admin list --cluster <cluster-id>
  sherlock-admin credential-admin bind-collector --cluster <cluster-id> --host <host> --collector <collector-id> --actor <operator-subject>
  sherlock-admin credential-admin unbind-collector --cluster <cluster-id> --host <host> --collector <collector-id> --actor <operator-subject>
  sherlock-admin credential-admin list-bindings --cluster <cluster-id>
  sherlock-admin human-auth grant-membership --issuer <verified-issuer> --subject <verified-subject> --cluster <cluster-id> --role CLUSTER_VIEWER|CLUSTER_ADMIN --actor <operator-subject>
  sherlock-admin human-auth revoke-membership --issuer <verified-issuer> --subject <verified-subject> --cluster <cluster-id> --actor <operator-subject>
  sherlock-admin human-auth show-membership --issuer <verified-issuer> --subject <verified-subject> --cluster <cluster-id>
  sherlock-admin human-auth grant-privilege --issuer <verified-issuer> --subject <verified-subject> --cluster <cluster-id> --privilege CREDENTIAL_MANAGE|POLICY_MANAGE|RAW_EVIDENCE --actor <operator-subject>
  sherlock-admin human-auth revoke-privilege --issuer <verified-issuer> --subject <verified-subject> --cluster <cluster-id> --privilege CREDENTIAL_MANAGE|POLICY_MANAGE|RAW_EVIDENCE --actor <operator-subject>
  sherlock-admin human-auth show-privilege --issuer <verified-issuer> --subject <verified-subject> --cluster <cluster-id> --privilege CREDENTIAL_MANAGE|POLICY_MANAGE|RAW_EVIDENCE
  sherlock-admin human-auth grant-platform --issuer <verified-issuer> --subject <verified-subject> --actor <operator-subject>
  sherlock-admin human-auth revoke-platform --issuer <verified-issuer> --subject <verified-subject> --actor <operator-subject>
  sherlock-admin human-auth show-platform --issuer <verified-issuer> --subject <verified-subject>
  sherlock-admin credential-rotate --actor <operator-subject> --writers-stopped
  sherlock-admin telemetry enroll --enrollment <reviewed-json-file> --expected-revision 0 --actor <local-operator>
  sherlock-admin telemetry status|revoke|rotate-key (see telemetry --help)
  sherlock-admin monitoring enroll --policy <reviewed-json-file> --expected-revision <0-or-control-revision> --actor <local-operator>
  sherlock-admin monitoring disable --cluster <cluster-id> --policy-id <policy-id> --expected-revision <control-revision> --actor <local-operator>
  sherlock-admin monitoring status --cluster <cluster-id> --policy-id <policy-id>
  sherlock-admin monitoring acknowledge --cluster <cluster-id> --policy-id <policy-id> --occurrence <occurrence> --expected-episode-version <version> --actor <local-operator>
  sherlock-admin monitoring owner --cluster <cluster-id> --policy-id <policy-id> --occurrence <occurrence> --expected-episode-version <version> --actor <local-operator> (--owner <owner> | --clear-owner)
  sherlock-admin monitoring maintenance --cluster <cluster-id> --policy-id <policy-id> --occurrence <occurrence> --expected-episode-version <version> --actor <local-operator> (--maintenance-seconds <1-86400> | --clear-maintenance)
  sherlock-admin monitoring review-recovery --cluster <cluster-id> --policy-id <policy-id> --occurrence <occurrence> --expected-episode-version <version> --actor <local-operator> --evidence-id <reviewed-evidence-id>

Monitoring actor values are local operator attribution, not verified principals.
Control revisions fence enrollment changes; occurrence and episode version fence episode changes.
Reviewed recovery records an evidence-bound disposition, not measured recovery.`

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) > 0 && arguments[0] == "slurm-failures" {
		return runSlurmFailureAdmin(arguments[1:], stdout, stderr)
	}
	if len(arguments) >= 1 && arguments[0] == "telemetry" {
		return runTelemetryAdmin(arguments[1:], stdout, stderr)
	}
	if len(arguments) >= 1 && arguments[0] == "monitoring" {
		return runMonitoringAdmin(arguments[1:], stdout, stderr)
	}
	if len(arguments) >= 2 && arguments[0] == "human-auth" {
		command, err := parseHumanCommand(arguments[1:])
		if err != nil {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		cfg, err := config.LoadControlAdmin()
		if err != nil {
			fmt.Fprintln(stderr, "invalid admin configuration")
			return 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := administerHuman(ctx, cfg.DatabaseURL, command, stdout); err != nil {
			fmt.Fprintln(stderr, "human authorization operation failed")
			return 1
		}
		return 0
	}
	if len(arguments) >= 2 && arguments[0] == "credential-admin" {
		command, err := parseCredentialAdminCommand(arguments[1:])
		if err != nil {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		cfg, err := config.LoadControlAdmin()
		if err != nil {
			fmt.Fprintln(stderr, "invalid admin configuration")
			return 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := administerCredentialAdmin(ctx, cfg.DatabaseURL, command, stdout); err != nil {
			fmt.Fprintln(stderr, "credential administrator operation failed")
			return 1
		}
		return 0
	}
	if len(arguments) >= 1 && arguments[0] == "credential-rotate" {
		command, err := parseCredentialRotationCommand(arguments[1:])
		if err != nil {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		cfg, err := config.LoadControlAdmin()
		if err != nil {
			fmt.Fprintln(stderr, "invalid admin configuration")
			return 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := administerCredentialRotation(ctx, cfg.DatabaseURL, command, stdout); err != nil {
			fmt.Fprintln(stderr, "credential rotation failed")
			return 1
		}
		return 0
	}
	if len(arguments) == 2 && validIdentifier(arguments[1]) && (arguments[0] == "bootstrap" || arguments[0] == "revoke") {
		cfg, err := config.LoadControlAdmin()
		if err != nil {
			fmt.Fprintln(stderr, "invalid admin configuration")
			return 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if arguments[0] == "bootstrap" {
			err = createBootstrap(ctx, cfg, domain.ClusterID(arguments[1]), stdout, stderr)
		} else {
			err = revokeCollector(ctx, cfg, domain.CollectorID(arguments[1]), stderr)
		}
		if err != nil {
			fmt.Fprintln(stderr, "collector administration failed")
			return 1
		}
		return 0
	}
	if len(arguments) < 2 || arguments[0] != "api-key" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	command, err := parseAPIKeyCommand(arguments[1:])
	if err != nil {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	cfg, err := config.LoadControlAdmin()
	if err != nil {
		fmt.Fprintln(stderr, "invalid admin configuration")
		return 2
	}
	hashKey, err := loadAPIKeyHashKey(os.Getenv("SHERLOCK_API_KEY_HASH_KEY"))
	if err != nil {
		fmt.Fprintln(stderr, "invalid admin configuration")
		return 2
	}
	defer destroy(hashKey)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := administerAPIKeys(ctx, cfg.DatabaseURL, hashKey, command, stdout, stderr); err != nil {
		// Do not print database errors or secret-bearing values.
		fmt.Fprintln(stderr, "API-key administration failed")
		return 1
	}
	return 0
}

type credentialAdminCommand struct {
	Action, ClusterID, Subject, Actor string
	Host, CollectorID                 string
}

type credentialRotationCommand struct{ Actor string }

func parseCredentialRotationCommand(arguments []string) (credentialRotationCommand, error) {
	flags := flag.NewFlagSet("credential-rotate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	actor := flags.String("actor", "", "operator subject")
	writersStopped := flags.Bool("writers-stopped", false, "confirm all credential writers are stopped")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || !*writersStopped || !validAccessSubjectCLI(*actor) {
		return credentialRotationCommand{}, fmt.Errorf("credential rotation requires --writers-stopped and a valid actor")
	}
	return credentialRotationCommand{Actor: *actor}, nil
}

func administerCredentialRotation(ctx context.Context, databaseURL string, command credentialRotationCommand, stdout io.Writer) error {
	keyringPath := strings.TrimSpace(os.Getenv("SHERLOCK_CREDENTIAL_KEYRING_FILE"))
	loaded, err := config.LoadCredentialKeyringFile(keyringPath)
	if err != nil {
		return err
	}
	defer func() {
		for _, key := range loaded.Keys {
			destroy(key)
		}
	}()
	ring, err := adminmanage.NewCredentialKeyring(loaded.ActiveVersion, loaded.Keys)
	if err != nil {
		return err
	}
	defer ring.Destroy()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	store, err := adminmanage.NewPostgresStore(pool, adminmanage.WithCredentialKeyring(ring))
	if err != nil {
		return err
	}
	var fingerprint [32]byte
	if _, err := io.ReadFull(rand.Reader, fingerprint[:]); err != nil {
		return err
	}
	var eventIDBytes [16]byte
	if _, err := io.ReadFull(rand.Reader, eventIDBytes[:]); err != nil {
		return err
	}
	audit := adminmanage.MutationAudit{
		EventID: "admin-" + hex.EncodeToString(eventIDBytes[:]), EventKind: adminmanage.EventCredentialKeyRotated,
		ReasonCode: "CREDENTIAL_KEY_ROTATED", ActorSubject: command.Actor, SessionFingerprint: fingerprint[:],
		RequestID: "credential-key-rotation", OccurredAt: time.Now().UTC(),
	}
	if err := store.RotateCredentials(ctx, ring, audit); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "credential rotation completed; saved credentials remain untested")
	return err
}

func parseCredentialAdminCommand(arguments []string) (credentialAdminCommand, error) {
	if len(arguments) < 1 {
		return credentialAdminCommand{}, fmt.Errorf("credential administrator action is required")
	}
	command := credentialAdminCommand{Action: arguments[0]}
	switch command.Action {
	case "grant", "revoke", "list", "bind-collector", "unbind-collector", "list-bindings":
	default:
		return credentialAdminCommand{}, fmt.Errorf("unknown credential administrator action")
	}
	flags := flag.NewFlagSet("credential-admin "+command.Action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	cluster := flags.String("cluster", "", "cluster identifier")
	subject := flags.String("subject", "", "Cloudflare Access subject")
	actor := flags.String("actor", "", "operator subject")
	host := flags.String("host", "", "head host name")
	collector := flags.String("collector", "", "collector identifier")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || !validIdentifier(*cluster) {
		return credentialAdminCommand{}, fmt.Errorf("invalid credential administrator arguments")
	}
	switch command.Action {
	case "grant", "revoke":
		if !validAccessSubjectCLI(*subject) || !validAccessSubjectCLI(*actor) {
			return credentialAdminCommand{}, fmt.Errorf("credential administrator subjects are required")
		}
	case "bind-collector", "unbind-collector":
		// A binding names an operator, a target host and one collector; it
		// never names an Access subject.
		if !validHostCLI(*host) || !validIdentifier(*collector) || !validAccessSubjectCLI(*actor) {
			return credentialAdminCommand{}, fmt.Errorf("credential target binding requires a host, a collector and an actor")
		}
	}
	command.ClusterID, command.Subject, command.Actor = *cluster, *subject, *actor
	command.Host, command.CollectorID = *host, *collector
	return command, nil
}

func administerCredentialAdmin(ctx context.Context, databaseURL string, command credentialAdminCommand, stdout io.Writer) error {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	store, err := adminmanage.NewPostgresStore(pool)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	switch command.Action {
	case "grant":
		return store.GrantCredentialAdmin(ctx, command.ClusterID, command.Subject, command.Actor, now)
	case "revoke":
		return store.RevokeCredentialAdmin(ctx, command.ClusterID, command.Subject, command.Actor, now)
	case "bind-collector":
		return store.BindCredentialTarget(ctx, command.ClusterID, command.Host, command.CollectorID, command.Actor, now)
	case "unbind-collector":
		return store.UnbindCredentialTarget(ctx, command.ClusterID, command.Host, command.CollectorID, command.Actor, now)
	case "list-bindings":
		bindings, err := store.ListCredentialTargetBindings(ctx, command.ClusterID)
		if err != nil {
			return err
		}
		for _, binding := range bindings {
			status := "ACTIVE"
			if binding.RevokedAt != nil {
				status = "REVOKED"
			}
			if _, err := fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", binding.Host, binding.CollectorID, status, binding.ApprovedAt.Format(time.RFC3339)); err != nil {
				return err
			}
		}
		return nil
	case "list":
		grants, err := store.ListCredentialAdminGrants(ctx, command.ClusterID)
		if err != nil {
			return err
		}
		for _, grant := range grants {
			status := "ACTIVE"
			if grant.RevokedAt != nil {
				status = "REVOKED"
			}
			if _, err := fmt.Fprintf(stdout, "%s\t%s\t%s\n", grant.AccessSubject, status, grant.GrantedAt.Format(time.RFC3339)); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("unsupported credential administrator action")
}

func validHostCLI(value string) bool {
	return len(value) > 0 && len(value) <= 256 && !strings.ContainsAny(value, "\x00\r\n\t ")
}

func validAccessSubjectCLI(value string) bool {
	return len(value) > 0 && len(value) <= 256 && !strings.ContainsAny(value, "\x00\r\n")
}

type APIKeyCommand struct {
	Action       string
	ClusterID    domain.ClusterID
	PublicID     string
	Label        string
	ExpiresIn    time.Duration
	Capabilities []auth.Capability
}

type repeatedStrings []string

func (values *repeatedStrings) String() string { return strings.Join(*values, ",") }
func (values *repeatedStrings) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func parseAPIKeyCommand(arguments []string) (APIKeyCommand, error) {
	if len(arguments) < 1 {
		return APIKeyCommand{}, fmt.Errorf("API-key action is required")
	}
	command := APIKeyCommand{Action: arguments[0]}
	flags := flag.NewFlagSet("api-key "+command.Action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	clusterID := flags.String("cluster", "", "cluster identifier")
	switch command.Action {
	case "create":
		label := flags.String("label", "", "safe key label")
		expiresIn := flags.Duration("expires-in", 90*24*time.Hour, "key lifetime")
		var rawCapabilities repeatedStrings
		flags.Var(&rawCapabilities, "capability", "allowed capability (repeatable)")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || !validIdentifier(*clusterID) || *label == "" || *expiresIn <= 0 || len(rawCapabilities) == 0 {
			return APIKeyCommand{}, fmt.Errorf("invalid API-key creation arguments")
		}
		for _, raw := range rawCapabilities {
			capability, err := auth.ParseCapability(raw)
			if err != nil {
				return APIKeyCommand{}, err
			}
			command.Capabilities = append(command.Capabilities, capability)
		}
		command.Label, command.ExpiresIn = *label, *expiresIn
	case "list":
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || !validIdentifier(*clusterID) {
			return APIKeyCommand{}, fmt.Errorf("invalid API-key listing arguments")
		}
	case "revoke":
		publicID := flags.String("key-id", "", "public API-key identifier")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || !validIdentifier(*clusterID) || *publicID == "" {
			return APIKeyCommand{}, fmt.Errorf("invalid API-key revocation arguments")
		}
		command.PublicID = *publicID
	default:
		return APIKeyCommand{}, fmt.Errorf("unknown API-key action")
	}
	command.ClusterID = domain.ClusterID(*clusterID)
	return command, nil
}

func administerAPIKeys(ctx context.Context, databaseURL string, hashKey []byte, command APIKeyCommand, stdout, stderr io.Writer) error {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	store, err := auth.NewPostgreSQLStore(pool)
	if err != nil {
		return err
	}
	clock := platform.SystemClock{}
	service, err := auth.NewService(store, clock, rand.Reader, hashKey)
	if err != nil {
		return err
	}
	defer service.Close()
	switch command.Action {
	case "create":
		issued, err := service.CreateKey(ctx, command.ClusterID, command.Label, command.Capabilities, clock.Now().Add(command.ExpiresIn))
		if err != nil {
			return err
		}
		defer issued.Plaintext.Destroy()
		if err := issued.Plaintext.WriteOnce(stdout); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(stdout); err != nil {
			return err
		}
		_, err = fmt.Fprintf(stderr, "public_key_id=%s cluster_id=%s expires_at=%s capabilities=%s\n", issued.Key.PublicID, issued.Key.ClusterID, issued.Key.ExpiresAt.Format(time.RFC3339), joinCapabilities(issued.Key.Capabilities))
		return err
	case "list":
		keys, err := service.ListKeys(ctx, command.ClusterID)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(stdout, "PUBLIC_KEY_ID\tLABEL\tSTATUS\tEXPIRES_AT\tLAST_USED_AT\tCAPABILITIES"); err != nil {
			return err
		}
		now := clock.Now()
		for _, key := range keys {
			status := "ACTIVE"
			if key.RevokedAt != nil {
				status = "REVOKED"
			} else if !key.ExpiresAt.After(now) {
				status = "EXPIRED"
			}
			lastUsed := "-"
			if key.LastUsedAt != nil {
				lastUsed = key.LastUsedAt.Format(time.RFC3339)
			}
			if _, err := fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\t%s\n", key.PublicID, strconv.Quote(key.Label), status, key.ExpiresAt.Format(time.RFC3339), lastUsed, joinCapabilities(key.Capabilities)); err != nil {
				return err
			}
		}
		return nil
	case "revoke":
		if err := service.RevokeKey(ctx, command.ClusterID, command.PublicID); err != nil {
			return err
		}
		_, err := fmt.Fprintf(stderr, "public_key_id=%s cluster_id=%s status=REVOKED\n", command.PublicID, command.ClusterID)
		return err
	default:
		return fmt.Errorf("unsupported API-key administration action")
	}
}

func loadAPIKeyHashKey(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, fmt.Errorf("SHERLOCK_API_KEY_HASH_KEY is required")
	}
	decoders := []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
	}
	for _, decode := range decoders {
		value, err := decode(encoded)
		if err == nil && len(value) >= 32 {
			return value, nil
		}
	}
	return nil, fmt.Errorf("SHERLOCK_API_KEY_HASH_KEY must encode at least 32 bytes")
}

func joinCapabilities(capabilities []auth.Capability) string {
	values := make([]string, len(capabilities))
	for index, capability := range capabilities {
		values[index] = string(capability)
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func destroy(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func revokeCollector(ctx context.Context, cfg config.ControlAdmin, collectorID domain.CollectorID, stderr io.Writer) error {
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	store, err := storepg.NewCollectorControlStore(pool)
	if err != nil {
		return err
	}
	if err := store.RevokeCollector(ctx, collectorID); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stderr, "collector_id=%s status=REVOKED\n", collectorID)
	return err
}

type unusedIssuer struct{}

func (unusedIssuer) Issue(domain.ClusterID, domain.CollectorID, []byte, time.Time, time.Duration) (collectorcontrol.IssuedIdentity, error) {
	return collectorcontrol.IssuedIdentity{}, fmt.Errorf("certificate issuer is unavailable in bootstrap-only process")
}

func createBootstrap(ctx context.Context, cfg config.ControlAdmin, clusterID domain.ClusterID, stdout, stderr io.Writer) error {
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM clusters WHERE cluster_id=$1 AND removed_at IS NULL)`, clusterID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("cluster is unavailable")
	}
	store, err := storepg.NewCollectorControlStore(pool)
	if err != nil {
		return err
	}
	service, err := collectorcontrol.NewIdentityService(store, unusedIssuer{}, platform.SystemClock{}, platform.RandomIDGenerator{}, rand.Reader, 5*time.Minute)
	if err != nil {
		return err
	}
	key, err := service.CreateBootstrapKey(ctx, clusterID, cfg.BootstrapTTL)
	if err != nil {
		return err
	}
	// The token is generated internally and emitted once, only on stdout. Safe
	// operational metadata is kept on stderr so redirection can isolate it.
	if _, err := fmt.Fprintln(stdout, key.Token); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stderr, "bootstrap_key_id=%s cluster_id=%s expires_at=%s\n", key.BootstrapKeyID, clusterID, key.ExpiresAt.UTC().Format(time.RFC3339))
	return err
}

func validIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && !strings.ContainsRune("._:-", r) {
			return false
		}
	}
	return true
}
