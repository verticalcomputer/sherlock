package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/testbed"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sherlock-testbed", flag.ContinueOnError)
	flags.SetOutput(stderr)
	suitePath := flags.String("suite", "test/testbed/v1/scenarios.json", "synthetic scenario suite")
	output := flags.String("output", "-", "JSON report path or stdout")
	baseline := flags.String("baseline", "", "prior report from the exact same suite")
	worker := flags.String("worker", "", "internal fresh-process worker investigation ID")
	stop := flags.Int("stop-after-actions", 0, "internal worker restart boundary")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if *baseline != "" && *baseline == *output {
		fmt.Fprintln(stderr, "baseline and output paths must differ")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	dsn := os.Getenv("SHERLOCK_TESTBED_DATABASE_URL")
	if dsn == "" {
		fmt.Fprintln(stderr, "use make testbed to create a disposable lab database")
		return 2
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintln(stderr, "testbed database configuration unavailable")
		return 2
	}
	defer pool.Close()
	var database string
	if err = pool.QueryRow(ctx, `SELECT current_database()`).Scan(&database); err != nil || !strings.HasPrefix(database, "sherlock_testbed_") {
		fmt.Fprintln(stderr, "a dedicated sherlock_testbed_ database is required")
		return 2
	}
	if *worker != "" {
		if err = testbed.Worker(ctx, pool, domain.InvestigationID(*worker), *stop); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	suite, digest, err := testbed.Load(*suitePath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	launch := func(ctx context.Context, id domain.InvestigationID, stop int) error {
		command := exec.CommandContext(ctx, exe, "-worker", string(id), "-stop-after-actions", fmt.Sprint(stop))
		command.Env = os.Environ()
		if raw, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("testbed worker: %w: %s", err, raw)
		}
		return nil
	}
	report, err := testbed.Run(ctx, pool, suite, digest, launch, true)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if binary, readErr := os.ReadFile(exe); readErr == nil {
		report.BinarySHA256 = domain.ChecksumSHA256(binary).String()
	}
	if build, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range build.Settings {
			switch setting.Key {
			case "vcs.revision":
				report.SourceRevision = setting.Value
			case "vcs.modified":
				report.SourceDirty = setting.Value == "true"
			}
		}
	}
	envelope := struct {
		testbed.Report
		Comparison *testbed.Comparison `json:"comparison,omitempty"`
	}{Report: report}
	if *baseline != "" {
		raw, err := os.ReadFile(*baseline)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		var prior testbed.Report
		if err = json.Unmarshal(raw, &prior); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		comparison, err := testbed.Compare(prior, report)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		envelope.Comparison = &comparison
	}
	raw, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	raw = append(raw, '\n')
	if *output == "-" {
		_, err = stdout.Write(raw)
	} else {
		err = writeReport(*output, raw)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if !report.Passed || envelope.Comparison != nil && !envelope.Comparison.Passed {
		return 1
	}
	return 0
}
func writeReport(path string, raw []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".testbed-report-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
