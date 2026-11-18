package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
	"github.com/verticalcomputer/sherlock/internal/store/postgres"
)

type archiveOpener func(context.Context, string, string) (alertassessment.ArchiveSource, error)

type command struct {
	name, config, suite, archive, out, run string
}

func parseArgs(args []string) (command, error) {
	var c command
	if len(args) == 0 {
		return c, alertassessment.ErrInvalid
	}
	c.name = args[0]
	allowed := map[string]*string{}
	switch c.name {
	case "validate-config":
		allowed["-config"] = &c.config
	case "replay":
		allowed["-suite"] = &c.suite
		allowed["-archive"] = &c.archive
		allowed["-out"] = &c.out
	case "export":
		allowed["-run"] = &c.run
		allowed["-out"] = &c.out
	default:
		return c, alertassessment.ErrInvalid
	}
	for i := 1; i < len(args); i += 2 {
		dst, ok := allowed[args[i]]
		if !ok || i+1 >= len(args) || args[i+1] == "" {
			return c, alertassessment.ErrInvalid
		}
		*dst = args[i+1]
		delete(allowed, args[i])
	}
	switch c.name {
	case "validate-config":
		if c.config == "" {
			return c, alertassessment.ErrInvalid
		}
	case "replay":
		if c.out == "" || (c.suite == "") == (c.archive == "") {
			return c, alertassessment.ErrInvalid
		}
	case "export":
		if c.out == "" || !alertassessment.ValidID(c.run, 128) {
			return c, alertassessment.ErrInvalid
		}
	}
	return c, nil
}

type commandError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func resultCode(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	e := commandError{Code: "IO_FAILURE", Message: "The operation could not read or write its required data."}
	status := 3
	var replayErr *alertassessment.ReplayError
	if errors.As(err, &replayErr) {
		switch replayErr.Code {
		case "OUTPUT_EXISTS":
			status, e = 2, commandError{"OUTPUT_EXISTS", "The output directory must be new."}
		case "RUN_NOT_CLOSED":
			status, e = 2, commandError{"RUN_NOT_CLOSED", "Export requires a closed assessment run."}
		case "RUN_EXPIRED":
			status, e = 2, commandError{"RUN_EXPIRED", "The assessment run has reached its retention cutoff."}
		case "REPLAY_UNAVAILABLE":
			status, e = 2, commandError{"REPLAY_UNAVAILABLE", "The pinned assessment implementation is unavailable."}
		case "EXPECTED_MISMATCH":
			status, e = 4, commandError{"EXPECTED_MISMATCH", "The replay decisions differ from the supplied expectations."}
		case "ASSESSMENT_DATABASE_URL_REQUIRED":
			status, e = 2, commandError{"ASSESSMENT_DATABASE_URL_REQUIRED", "Export requires SHERLOCK_ASSESSMENT_DATABASE_URL."}
		}
	} else if errors.Is(err, alertassessment.ErrInvalid) {
		status, e = 2, commandError{"INVALID_INPUT", "Arguments, schema, version or resource limits are invalid."}
	}
	_ = json.NewEncoder(stderr).Encode(e)
	return status
}

func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer, open archiveOpener) int {
	c, err := parseArgs(args)
	if err != nil {
		return resultCode(err, stderr)
	}
	registry, err := alertassessment.NewRegistry(cooling.Category{})
	if err != nil {
		return resultCode(err, stderr)
	}
	switch c.name {
	case "validate-config":
		var raw []byte
		raw, err = alertassessment.ReadLocalFile(c.config, 64<<10)
		if err != nil {
			break
		}
		var cfg alertassessment.Config
		cfg, err = alertassessment.ParseConfig(ctx, raw, registry)
		if err != nil {
			err = fmt.Errorf("%w: configuration schema", alertassessment.ErrInvalid)
			break
		}
		var hash string
		hash, err = cfg.Hash()
		if err == nil {
			err = json.NewEncoder(stdout).Encode(map[string]string{"status": "VALID", "config_hash": hash})
		}
	case "replay":
		err = replayCommand(ctx, c, registry, stdout)
	case "export":
		err = exportCommand(ctx, c, getenv, stdout, open)
	}
	return resultCode(err, stderr)
}

func rejectExisting(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return &alertassessment.ReplayError{Code: "OUTPUT_EXISTS"}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func replayCommand(ctx context.Context, c command, registry *alertassessment.Registry, stdout io.Writer) error {
	if err := rejectExisting(c.out); err != nil {
		return err
	}
	var e *alertassessment.Engine
	var observed *alertassessment.Engine
	var suite alertassessment.Suite
	var reproduction alertassessment.ArchiveReplay
	var idealEvidence *os.File
	provenance := ""
	mismatch := false
	if c.suite != "" {
		b, err := alertassessment.ReadLocalFile(c.suite, 16<<20)
		if err != nil {
			return err
		}
		suite, err = alertassessment.ParseSuite(b, registry)
		if err != nil {
			return err
		}
		e, err = alertassessment.Replay(ctx, suite, registry)
		if err != nil {
			return err
		}
		provenance = suite.Provenance
		mismatch = alertassessment.CheckExpected(e, suite.Expected) != nil
	} else {
		var err error
		idealEvidence, err = os.CreateTemp("", "sherlock-assessment-ideal-*")
		if err != nil {
			return err
		}
		defer func() { _ = idealEvidence.Close(); _ = os.Remove(idealEvidence.Name()) }()
		reproduction, err = alertassessment.ReplayArchiveWithEvidence(ctx, c.archive, registry, idealEvidence)
		if err != nil {
			return err
		}
		e, observed = reproduction.Ideal, reproduction.Observed
		provenance = reproduction.Manifest.Provenance
		mismatch = len(reproduction.Mismatched) > 0
	}
	r, err := e.ReportWithLegacy(provenance, suite.Labels, suite.Legacy)
	if err != nil {
		return err
	}
	if observed != nil {
		r.Comparison = "IDEAL_ARCHIVE_REPLAY"
		r.ExecutionNotReproduced = reproduction.ExecutionNotReproduced
	}
	semantic, err := alertassessment.SemanticReport(r)
	if err != nil {
		return err
	}
	if err := alertassessment.PrivateDirectory(c.out); err != nil {
		return err
	}
	write := func(name string, write func(io.Writer) error) error {
		f, err := alertassessment.OpenPrivateFile(c.out, name)
		if err != nil {
			return err
		}
		return errors.Join(write(f), f.Sync(), f.Close())
	}
	for _, entry := range []struct {
		name string
		fn   func(io.Writer) error
	}{
		{"semantic.json", func(w io.Writer) error { _, err := w.Write(append(semantic, '\n')); return err }},
		{"execution.json", func(w io.Writer) error { return json.NewEncoder(w).Encode(r.Execution) }},
		{"report.md", func(w io.Writer) error { return alertassessment.WriteMarkdownReport(w, r) }},
		{"labels.ndjson", func(w io.Writer) error {
			enc := json.NewEncoder(w)
			_, err := e.ScoreWithLegacy(suite.Labels, suite.Legacy, func(row alertassessment.ScoreRow) error { return enc.Encode(row) })
			return err
		}},
		{"evidence.ndjson", func(w io.Writer) error {
			if observed != nil {
				if err := alertassessment.WriteArchiveEvidence(ctx, c.archive, w); err != nil {
					return err
				}
				if _, err := idealEvidence.Seek(0, io.SeekStart); err != nil {
					return err
				}
				_, err := io.Copy(w, idealEvidence)
				return err
			}
			return e.WriteEvidence(w)
		}},
	} {
		if err := write(entry.name, entry.fn); err != nil {
			return err
		}
	}
	if observed != nil {
		actual, err := observed.ReportWithLegacy(provenance, nil, nil)
		if err != nil {
			return err
		}
		actual.ExecutionNotReproduced = reproduction.ExecutionNotReproduced
		if err = write("observed.json", func(w io.Writer) error { return json.NewEncoder(w).Encode(actual) }); err != nil {
			return err
		}
		if err = write("comparison.json", func(w io.Writer) error {
			return json.NewEncoder(w).Encode(map[string]any{"execution_not_reproduced": reproduction.ExecutionNotReproduced, "mismatched": reproduction.Mismatched})
		}); err != nil {
			return err
		}
	}
	manifest := map[string]any{"schema": int64(1), "complete": true, "run_id": e.Config.RunID, "semantic_sha256": fmt.Sprintf("%x", sha256.Sum256(semantic)), "expected_match": !mismatch}
	if err := alertassessment.CompletePrivateDirectory(c.out, manifest); err != nil {
		return err
	}
	if mismatch {
		return &alertassessment.ReplayError{Code: "EXPECTED_MISMATCH"}
	}
	return json.NewEncoder(stdout).Encode(manifest)
}

func exportCommand(ctx context.Context, c command, getenv func(string) string, stdout io.Writer, open archiveOpener) error {
	if err := rejectExisting(c.out); err != nil {
		return err
	}
	dsn := getenv("SHERLOCK_ASSESSMENT_DATABASE_URL")
	if dsn == "" {
		return &alertassessment.ReplayError{Code: "ASSESSMENT_DATABASE_URL_REQUIRED"}
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	source, err := open(bounded, dsn, c.run)
	if err != nil {
		return err
	}
	defer source.Close(context.Background())
	m, err := alertassessment.WriteArchive(bounded, filepath.Clean(c.out), source)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(m)
}

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Getenv, os.Stdout, os.Stderr, postgres.OpenAssessmentArchive))
}
