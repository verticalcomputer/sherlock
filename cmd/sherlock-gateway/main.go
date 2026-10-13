package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/verticalcomputer/sherlock/internal/gatewaytelemetry"
	"github.com/verticalcomputer/sherlock/internal/nodeidentity"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetrylocal"
)

type observer struct{ logger *slog.Logger }

// Release tooling binds these to the reviewed source manifest. Binary checksums
// remain external; a fixture's supplied node build label is not this provenance.
var releaseVersion, releaseSourceSHA256 string

func (o observer) Delivery(id, code string) {
	if code != "EMPTY" {
		o.logger.Info("telemetry.delivery", "enrollment_id", id, "code", code)
	}
}

const usage = `sherlock-gateway --config <absolute-protected-file> --fixture
sherlock-gateway relay-identity --config <absolute-protected-file> --request <protected-public-csr-json> --token-file <protected-token> --bundle-output <new-protected-public-bundle>
Synthetic fixture.v1 only. No service installation or command interface. Tokens and private keys are never printed.`

func run(ctx context.Context, args []string, out, errs io.Writer) int {
	if len(args) == 1 && args[0] == "version" {
		version, source := releaseVersion, releaseSourceSHA256
		if version == "" {
			version = "DEVELOPMENT"
		}
		if source == "" {
			source = "UNKNOWN"
		}
		if json.NewEncoder(out).Encode(struct {
			Version string `json:"version"`
			Source  string `json:"source_sha256"`
			Profile string `json:"profile"`
		}{version, source, telemetry.FixtureProfile}) != nil {
			return 1
		}
		return 0
	}
	relay := len(args) > 0 && args[0] == "relay-identity"
	if relay {
		args = args[1:]
	}
	flags := flag.NewFlagSet("sherlock-gateway", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "")
	fixture := flags.Bool("fixture", false, "")
	requestPath, tokenPath, bundlePath := "", "", ""
	if relay {
		flags.StringVar(&requestPath, "request", "", "")
		flags.StringVar(&tokenPath, "token-file", "", "")
		flags.StringVar(&bundlePath, "bundle-output", "", "")
	}
	if e := flags.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			fmt.Fprintln(out, usage)
			return 0
		}
		fmt.Fprintln(errs, "gateway arguments invalid")
		return 2
	}
	if flags.NArg() != 0 || *path == "" || !relay && !*fixture || relay && (requestPath == "" || tokenPath == "" || bundlePath == "" || *fixture) {
		fmt.Fprintln(errs, usage)
		return 2
	}
	cfg, e := gatewaytelemetry.LoadConfig(*path)
	if e != nil {
		fmt.Fprintln(errs, "gateway configuration invalid")
		return 2
	}
	if relay {
		body, e := telemetrylocal.ReadProtected(requestPath, nodeidentity.MaxRequestBytes)
		var request nodeidentity.Request
		if e != nil || telemetry.DecodeStrictJSON(body, "", &request) != nil {
			fmt.Fprintln(errs, "node identity request invalid")
			return 2
		}
		token, e := telemetrylocal.ReadProtected(tokenPath, 128)
		if e != nil {
			fmt.Fprintln(errs, "node bootstrap token invalid")
			return 2
		}
		defer clear(token)
		bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		bundle, e := gatewaytelemetry.RelayIdentity(bounded, cfg, string(token), request)
		if e != nil {
			fmt.Fprintln(errs, "node certificate relay unavailable")
			return 1
		}
		encoded, e := json.Marshal(bundle)
		if e != nil || telemetrylocal.WriteNewProtected(bundlePath, encoded) != nil {
			fmt.Fprintln(errs, "node certificate output unavailable")
			return 1
		}
		fmt.Fprintln(out, `{"stored":true}`)
		return 0
	}
	logger := slog.New(slog.NewJSONHandler(errs, nil))
	if e = gatewaytelemetry.Serve(ctx, cfg, observer{logger}); e != nil && !errors.Is(e, context.Canceled) {
		logger.Error("gateway.stopped", "reason", "startup or runtime failure")
		return 1
	}
	return 0
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
