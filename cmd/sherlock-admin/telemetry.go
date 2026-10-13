package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/nodeidentity"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetrylocal"
)

const telemetryAdminUsage = `usage:
  sherlock-admin telemetry enroll --enrollment <reviewed-json-file> --expected-revision 0 --actor <local-operator>
  sherlock-admin telemetry status --cluster <cluster-id> --collector <gateway-id> --enrollment-id <enrollment-id>
  sherlock-admin telemetry revoke --cluster <cluster-id> --enrollment-id <enrollment-id> --expected-revision <control-revision> --actor <local-operator>
  sherlock-admin telemetry rotate-key --cluster <cluster-id> --enrollment-id <enrollment-id> --expected-revision <control-revision> --key-id <new-key-id> --public-key <unpadded-base64-public-key> --actor <local-operator> [--compromised]
  sherlock-admin telemetry mint-node-token --cluster <cluster-id> --collector <gateway-id> --request <absolute-protected-csr-json> --expected-revision <control-revision> --actor <local-operator> --token-output <new-absolute-protected-file>

Actor is supplied local operator attribution, not a verified principal.
Closed fixture.v1, linux.host.v1 and linux.rootfs.v1 history profiles may be
enrolled. source_profiles binds declared source IDs; omission retains fixture.v1.
Minting a token approves an exact
node-generated CSR for authenticated gateway relay; it installs nothing and
grants no hardware/repair authority. The token is never printed.
Two key epochs maximum; third rotation requires a future ownership-retirement gate.`

type telemetryAdminCommand struct {
	Action, Cluster, Collector, ID, Actor, Path, KeyID, Public string
	Expected                                                   int64
	Compromised                                                bool
	RequestPath, TokenOutput                                   string
}

func parseTelemetryAdmin(arguments []string) (out telemetryAdminCommand, err error) {
	if len(arguments) == 0 {
		return out, telemetry.ErrInvalid
	}
	out.Action = arguments[0]
	allowed := map[string]bool{}
	allow := func(names ...string) {
		for _, name := range names {
			allowed[name] = true
		}
	}
	switch out.Action {
	case "enroll":
		allow("enrollment", "expected-revision", "actor")
	case "status":
		allow("cluster", "collector", "enrollment-id")
	case "revoke":
		allow("cluster", "enrollment-id", "expected-revision", "actor")
	case "rotate-key":
		allow("cluster", "enrollment-id", "expected-revision", "actor", "key-id", "public-key", "compromised")
	case "mint-node-token":
		allow("cluster", "collector", "request", "expected-revision", "actor", "token-output")
	default:
		return out, telemetry.ErrInvalid
	}
	flags := flag.NewFlagSet("telemetry", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&out.Cluster, "cluster", "", "")
	flags.StringVar(&out.Collector, "collector", "", "")
	flags.StringVar(&out.ID, "enrollment-id", "", "")
	flags.StringVar(&out.Actor, "actor", "", "")
	flags.StringVar(&out.Path, "enrollment", "", "")
	flags.Int64Var(&out.Expected, "expected-revision", -1, "")
	flags.StringVar(&out.KeyID, "key-id", "", "")
	flags.StringVar(&out.Public, "public-key", "", "")
	flags.BoolVar(&out.Compromised, "compromised", false, "")
	flags.StringVar(&out.RequestPath, "request", "", "")
	flags.StringVar(&out.TokenOutput, "token-output", "", "")
	if uniqueMonitoringFlags(arguments[1:], flags) != nil || flags.Parse(arguments[1:]) != nil || flags.NArg() != 0 {
		return out, telemetry.ErrInvalid
	}
	invalid := false
	flags.Visit(func(f *flag.Flag) {
		if !allowed[f.Name] {
			invalid = true
		}
	})
	if invalid {
		return out, telemetry.ErrInvalid
	}
	if out.Action == "enroll" {
		if out.Path == "" || out.Expected != 0 || !validMonitoringActor(out.Actor) {
			return out, telemetry.ErrInvalid
		}
		return out, nil
	}
	if out.Action == "mint-node-token" {
		if !validIdentifier(out.Cluster) || !validIdentifier(out.Collector) || !filepath.IsAbs(out.RequestPath) || filepath.Clean(out.RequestPath) != out.RequestPath || !filepath.IsAbs(out.TokenOutput) || filepath.Clean(out.TokenOutput) != out.TokenOutput || out.Expected < 1 || !validMonitoringActor(out.Actor) {
			return out, telemetry.ErrInvalid
		}
		return out, nil
	}
	if !validIdentifier(out.Cluster) || !validIdentifier(out.ID) {
		return out, telemetry.ErrInvalid
	}
	if out.Action == "status" {
		if !validIdentifier(out.Collector) {
			return out, telemetry.ErrInvalid
		}
		return out, nil
	}
	if out.Expected < 1 || !validMonitoringActor(out.Actor) {
		return out, telemetry.ErrInvalid
	}
	if out.Action == "rotate-key" {
		if !validIdentifier(out.KeyID) {
			return out, telemetry.ErrInvalid
		}
		if _, err = telemetry.ParseNodePublicKey(telemetry.NodeKey{PublicKeyBase64: out.Public}); err != nil {
			return out, telemetry.ErrInvalid
		}
	}
	return out, nil
}
func readTelemetryEnrollment(path string) (out storepg.EnrollmentRequest, err error) {
	file, err := os.Open(path)
	if err != nil {
		return out, telemetry.ErrInvalid
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(body) > 64<<10 {
		return out, telemetry.ErrInvalid
	}
	if telemetry.DecodeStrictJSON(body, "", &out) != nil {
		return out, telemetry.ErrInvalid
	}
	return out, nil
}
func runTelemetryAdmin(arguments []string, stdout, stderr io.Writer) int {
	command, err := parseTelemetryAdmin(arguments)
	if err != nil {
		fmt.Fprintln(stderr, telemetryAdminUsage)
		return 2
	}
	var enrollment storepg.EnrollmentRequest
	var identityRequest nodeidentity.Request
	if command.Action == "enroll" {
		enrollment, err = readTelemetryEnrollment(command.Path)
		if err != nil {
			fmt.Fprintln(stderr, "invalid telemetry enrollment document")
			return 2
		}
	}
	if command.Action == "mint-node-token" {
		body, e := telemetrylocal.ReadProtected(command.RequestPath, nodeidentity.MaxRequestBytes)
		if e != nil || telemetry.DecodeStrictJSON(body, "", &identityRequest) != nil {
			fmt.Fprintln(stderr, "invalid node identity request")
			return 2
		}
		if _, e = nodeidentity.ValidateRequest(identityRequest); e != nil || identityRequest.Scope.ClusterID != command.Cluster {
			fmt.Fprintln(stderr, "invalid node identity request")
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
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintln(stderr, "telemetry operation failed")
		return 1
	}
	defer pool.Close()
	store := storepg.NewTelemetryStore(pool)
	var result any
	switch command.Action {
	case "enroll":
		result, err = store.CreateEnrollment(ctx, enrollment, 0, command.Actor)
	case "status":
		result, err = store.Status(ctx, domain.ClusterID(command.Cluster), domain.CollectorID(command.Collector), command.ID)
	case "revoke":
		var revision int64
		revision, err = store.RevokeEnrollment(ctx, domain.ClusterID(command.Cluster), command.ID, command.Expected, command.Actor)
		result = struct {
			Revision int64 `json:"control_revision"`
		}{revision}
	case "rotate-key":
		result, err = store.RotateKey(ctx, domain.ClusterID(command.Cluster), command.ID, command.Expected, command.KeyID, command.Public, command.Actor, command.Compromised)
	case "mint-node-token":
		var token string
		token, err = store.MintNodeBootstrap(ctx, domain.ClusterID(command.Cluster), domain.CollectorID(command.Collector), identityRequest, command.Expected, command.Actor)
		if err == nil {
			err = telemetrylocal.WriteNewProtected(command.TokenOutput, []byte(token))
		}
		result = struct {
			Minted bool `json:"minted"`
		}{err == nil}
	}
	if err != nil {
		message := "telemetry operation failed"
		switch {
		case errors.Is(err, telemetry.ErrInvalid):
			message = "invalid telemetry operation"
		case errors.Is(err, telemetry.ErrConflict):
			message = "telemetry revision or immutable identity conflict"
		case errors.Is(err, telemetry.ErrUnauthorized):
			message = "telemetry authority unavailable"
		case errors.Is(err, telemetry.ErrBackpressure):
			message = "telemetry capacity or ownership retirement gate reached"
		}
		fmt.Fprintln(stderr, message)
		return 1
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, "telemetry output failed")
		return 1
	}
	return 0
}
