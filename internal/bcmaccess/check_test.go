package bcmaccess

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const canary = "synthetic-sudo-canary-9f3a"

// documentedListingJSON is grounded directly in the admin manual's "Creating
// JSON Format Output From A Table Format Output In cmsh" example: keys are
// the column titles, including the documented "hostname (key)" spelling.
const documentedListingJSON = `[{"type":"HeadNode","hostname (key)":"fixture1-zone1-headnode","status":"[ UP ]"},{"type":"PhysicalNode","hostname (key)":"node001","status":"[ UP ]"}]`

// observedReleaseFile is the exact two-line content recorded in the
// September 21 CLI qualification (stat/od of /etc/cm-release on the pilot
// head). The other release-file fixtures below are synthetic, constructed to
// exercise the reviewed matching rule.
const observedReleaseFile = "Cluster Manager v10.0\nmaster\n"

type scriptedRunner struct {
	t        *testing.T
	calls    []CommandSpec
	precheck CommandOutcome
	listing  CommandOutcome
}

// defaultPrecheck is the "a password is required" outcome that lets the
// check proceed past the sudo policy pre-check to fetch the credential and
// run the listing. Most fixtures below only care about listing behavior and
// use this as their precheck outcome.
func defaultPrecheck() CommandOutcome {
	return CommandOutcome{Started: true, ExitCode: 1, Stderr: []byte("sudo: a password is required\n")}
}

func (r *scriptedRunner) Run(_ context.Context, spec CommandSpec) CommandOutcome {
	spec.Stdin = append([]byte(nil), spec.Stdin...)
	r.calls = append(r.calls, spec)
	if len(spec.Args) > 0 && spec.Args[0] == "-n" && len(r.calls) == 1 {
		return r.precheck
	}
	return r.listing
}

func samplePlan(host, username string) domain.CredentialAccessTestPlan {
	now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	return domain.CredentialAccessTestPlan{
		SchemaVersion: domain.CredentialAccessTestSchemaVersion, TestID: "ctest_sample", ClusterID: "pilot-cluster",
		Operation: domain.CredentialAccessTestOperation, Host: host, Purpose: domain.CredentialAccessTestPurpose, Username: username,
		CredentialID: "cred_sample", CredentialVersion: 3, RequestedAt: now, Deadline: now.Add(10 * time.Minute),
		Limits: domain.CredentialAccessTestLimits{TimeoutSeconds: 30, MaxOutputBytes: 64 << 10},
	}
}

func executables(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	sudo, cmsh := filepath.Join(dir, "sudo"), filepath.Join(dir, "cmsh")
	for _, path := range []string{sudo, cmsh} {
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return sudo, cmsh
}

// releaseFile writes content to a fresh path in a temp dir and returns it.
// Passing "" (missing) returns a path that is never created.
func releaseFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "cm-release")
	if content == "" {
		return filepath.Join(dir, "missing-cm-release")
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func newChecker(t *testing.T, runner Runner, sudo, cmsh, release string) *Checker {
	t.Helper()
	checker, err := New(Config{SudoPath: sudo, CmshPath: cmsh, ReleaseFile: release, ExpectedHost: "fixture1-zone1-headnode", Runner: runner,
		Hostname:    func() (string, error) { return "fixture1-zone1-headnode.example.test", nil },
		CurrentUser: func() (*user.User, error) { return &user.User{Username: "fixture_user_1"}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return checker
}

// newQualifiedChecker is newChecker pre-wired with the observed, supported
// release file, for tests that only care about pre-check/listing behavior.
func newQualifiedChecker(t *testing.T, runner Runner, sudo, cmsh string) *Checker {
	t.Helper()
	return newChecker(t, runner, sudo, cmsh, releaseFile(t, observedReleaseFile))
}

func fetchOK(secret []byte) (func(context.Context) ([]byte, error), *bool) {
	called := false
	return func(context.Context) ([]byte, error) {
		called = true
		return append([]byte(nil), secret...), nil
	}, &called
}

func fetchErr(err error) (func(context.Context) ([]byte, error), *bool) {
	called := false
	return func(context.Context) ([]byte, error) {
		called = true
		return nil, err
	}, &called
}

func assertNoCanary(t *testing.T, result domain.CredentialAccessTestResult) {
	t.Helper()
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), canary) {
		t.Fatalf("result leaked the synthetic secret: %s", encoded)
	}
	if err := domain.ValidateCredentialAccessTestResult(result); err != nil {
		t.Fatalf("result failed contract validation: %v (%s)", err, encoded)
	}
}

// --- Version detection (synthetic and documented fixtures) ---

func TestDetectVersionClassifiesReleaseFile(t *testing.T) {
	cases := []struct {
		name    string
		content string
		missing bool
		version string
		ok      bool
	}{
		{"documented: observed pilot file, major 10 supported", observedReleaseFile, false, "10.0", true},
		{"synthetic: unsupported major", "Cluster Manager v9.2\n", false, "9.2", false},
		{"synthetic: missing v prefix", "v10.0\n", false, "", false},
		{"synthetic: extra leading words", "Version 10.0 of something\n", false, "", false},
		{"synthetic: empty file", "", false, "", false},
		{"synthetic: missing file", "", true, "", false},
		{"synthetic: three leading garbage lines before a valid one", "garbage one\ngarbage two\ngarbage three\nCluster Manager v10.0\n", false, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var path string
			if tc.missing {
				path = releaseFile(t, "")
			} else if tc.content == "" {
				dir := t.TempDir()
				path = filepath.Join(dir, "cm-release")
				if err := os.WriteFile(path, nil, 0o644); err != nil {
					t.Fatal(err)
				}
			} else {
				path = releaseFile(t, tc.content)
			}
			sudo, cmsh := executables(t)
			checker := newChecker(t, &scriptedRunner{t: t}, sudo, cmsh, path)
			version, _, ok := checker.detectVersion()
			if ok != tc.ok {
				t.Fatalf("ok=%v want %v (version=%q)", ok, tc.ok, version)
			}
			if tc.ok && version != tc.version {
				t.Fatalf("version=%q want %q", version, tc.version)
			}
		})
	}
}

func TestCheckReportsVersionUnsupportedBeforeAnyCommandRuns(t *testing.T) {
	sudo, cmsh := executables(t)
	runner := &scriptedRunner{t: t}
	checker := newChecker(t, runner, sudo, cmsh, releaseFile(t, "Cluster Manager v9.2\n"))
	fetch, called := fetchOK([]byte(canary))
	result := checker.Check(context.Background(), samplePlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch)
	assertNoCanary(t, result)
	if result.Outcome != domain.CredentialAccessVersionUnsupported {
		t.Fatalf("outcome=%s want %s", result.Outcome, domain.CredentialAccessVersionUnsupported)
	}
	if len(runner.calls) != 0 {
		t.Fatal("no sudo command may run when the version is unsupported")
	}
	if *called {
		t.Fatal("credential must not be fetched when the version is unsupported")
	}
}

// --- Sudo policy / passwordless pre-check ---

func TestPasswordlessBCMAccessUsesNoSecretAndRetainsOnlyDiscoveryRows(t *testing.T) {
	sudo, cmsh := executables(t)
	for _, operation := range []string{domain.CredentialAccessTestOperation, domain.CredentialInventoryDiscoveryOperation} {
		plan := samplePlan("fixture1-zone1-headnode", "fixture_user_1")
		plan.Purpose = domain.CredentialAccessPasswordlessPurpose
		plan.Operation = operation
		runner := &scriptedRunner{t: t, precheck: CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte(documentedListingJSON)}, listing: CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte(documentedListingJSON)}}
		fetchCalled := false
		result := newQualifiedChecker(t, runner, sudo, cmsh).Check(context.Background(), plan, 1, func(context.Context) ([]byte, error) {
			fetchCalled = true
			return nil, errors.New("unexpected credential fetch")
		})
		if fetchCalled || result.Outcome != domain.CredentialAccessPasswordlessVerified {
			t.Fatalf("operation %s: fetched=%v result=%+v", operation, fetchCalled, result)
		}
		wantCalls, wantRows := 1, 0
		if operation == domain.CredentialInventoryDiscoveryOperation {
			wantCalls, wantRows = 2, 2
			if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != inventoryListingCommand {
				t.Fatalf("inventory command = %q", got)
			}
		}
		if len(runner.calls) != wantCalls || len(result.Devices) != wantRows {
			t.Fatalf("operation %s: calls=%d devices=%d", operation, len(runner.calls), len(result.Devices))
		}
		if err := domain.ValidateCredentialAccessTestResultForPlan(result, plan, 1); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPasswordlessBCMAccessRejectsPasswordRequirement(t *testing.T) {
	sudo, cmsh := executables(t)
	plan := samplePlan("fixture1-zone1-headnode", "fixture_user_1")
	plan.Purpose = domain.CredentialAccessPasswordlessPurpose
	runner := &scriptedRunner{t: t, precheck: defaultPrecheck()}
	result := newQualifiedChecker(t, runner, sudo, cmsh).Check(context.Background(), plan, 1, func(context.Context) ([]byte, error) {
		t.Fatal("passwordless authorization fetched a password")
		return nil, nil
	})
	if result.Outcome != domain.CredentialAccessSudoAuthFailed || len(runner.calls) != 1 {
		t.Fatalf("result=%+v calls=%d", result, len(runner.calls))
	}
}

func TestCheckSudoPolicyPrecheckOutcomes(t *testing.T) {
	sudo, cmsh := executables(t)
	cases := []struct {
		name           string
		precheck       CommandOutcome
		outcome        domain.CredentialAccessOutcome
		fetchExpected  bool
		listingExpects bool
	}{
		// (b) True NOPASSWD: the -n probe exits 0 with a valid device
		// listing on stdout, sent without ever spending a password.
		{"exit 0 with valid JSON -> passwordless, credential never fetched", CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte(documentedListingJSON)}, domain.CredentialAccessSudoPasswordless, false, false},
		// (c) exit 0 but the output is not the reviewed listing shape: sudo
		// ran something with no password, but it cannot be trusted, so it
		// still stops before any credential is fetched.
		{"exit 0 with error text -> output unexpected, credential never fetched", CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte("ERROR: could not find certificate and key files\n")}, domain.CredentialAccessOutputUnexpected, false, false},
		{"exit 0 with empty stdout -> output unexpected, credential never fetched", CommandOutcome{Started: true, ExitCode: 0}, domain.CredentialAccessOutputUnexpected, false, false},
		{"exit 0 but truncated -> output unexpected, credential never fetched", CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte(documentedListingJSON), Truncated: true}, domain.CredentialAccessOutputUnexpected, false, false},
		// (a) Mixed policy: a hypothetical "-l" would have succeeded, but
		// the execution-based -n probe correctly reports that a password is
		// required, so the check proceeds to fetch and verify.
		{"a password is required -> proceeds", CommandOutcome{Started: true, ExitCode: 1, Stderr: []byte("sudo: a password is required\n")}, domain.CredentialAccessVerified, true, true},
		// (d) denial.
		{"sudoers denial -> policy unsupported, credential never fetched", CommandOutcome{Started: true, ExitCode: 1, Stderr: []byte("fixture_user_1 is not in the sudoers file.")}, domain.CredentialAccessSudoPolicyUnsupported, false, false},
		{"unexpected response -> prompt unexpected", CommandOutcome{Started: true, ExitCode: 1, Stderr: []byte("Verification code: ")}, domain.CredentialAccessSudoPromptUnexpected, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &scriptedRunner{t: t, precheck: tc.precheck, listing: CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte(documentedListingJSON), Stderr: []byte(SudoPrompt)}}
			checker := newQualifiedChecker(t, runner, sudo, cmsh)
			fetch, called := fetchOK([]byte(canary))
			result := checker.Check(context.Background(), samplePlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch)
			assertNoCanary(t, result)
			if result.Outcome != tc.outcome {
				t.Fatalf("outcome=%s want %s (%s)", result.Outcome, tc.outcome, result.Summary)
			}
			if *called != tc.fetchExpected {
				t.Fatalf("credential fetched=%v want %v", *called, tc.fetchExpected)
			}
			ranListing := len(runner.calls) > 1
			if ranListing != tc.listingExpects {
				t.Fatalf("listing ran=%v want %v (calls=%d)", ranListing, tc.listingExpects, len(runner.calls))
			}
		})
	}
}

// TestCheckSudoPolicyPrecheckMixedListpwPolicy is scenario (a) from the
// round-3 review in isolation: sudoers `listpw` could make a hypothetical
// "sudo -n -l" exit 0 even though the reviewed command still requires a
// password. The probe never uses "-l", so it correctly reports "a password
// is required", the check proceeds to fetch and use the credential exactly
// once (on the -S listing call only), and verifies successfully.
func TestCheckSudoPolicyPrecheckMixedListpwPolicy(t *testing.T) {
	sudo, cmsh := executables(t)
	runner := &scriptedRunner{
		t:        t,
		precheck: CommandOutcome{Started: true, ExitCode: 1, Stderr: []byte("sudo: a password is required\n")},
		listing:  CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte(documentedListingJSON), Stderr: []byte(SudoPrompt)},
	}
	checker := newQualifiedChecker(t, runner, sudo, cmsh)
	fetch, called := fetchOK([]byte(canary))
	result := checker.Check(context.Background(), samplePlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch)
	assertNoCanary(t, result)
	if result.Outcome != domain.CredentialAccessVerified {
		t.Fatalf("outcome=%s want %s (%s)", result.Outcome, domain.CredentialAccessVerified, result.Summary)
	}
	if !*called {
		t.Fatal("credential should have been fetched exactly once")
	}
	if len(runner.calls) != 2 {
		t.Fatalf("expected exactly one precheck call and one listing call, got %d", len(runner.calls))
	}
	if len(runner.calls[0].Stdin) != 0 {
		t.Fatal("the probe must never receive the password on stdin")
	}
	if string(runner.calls[1].Stdin) != canary+"\n" {
		t.Fatalf("the password must reach sudo only through the listing call's stdin, got %q", runner.calls[1].Stdin)
	}
}

// --- Fixed argv, stdin isolation ---

func TestCheckUsesExactFixedArgvForPrecheckAndListing(t *testing.T) {
	sudo, cmsh := executables(t)
	runner := &scriptedRunner{t: t, precheck: defaultPrecheck(), listing: CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte(documentedListingJSON), Stderr: []byte(SudoPrompt)}}
	checker := newQualifiedChecker(t, runner, sudo, cmsh)
	fetch, _ := fetchOK([]byte(canary))
	result := checker.Check(context.Background(), samplePlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch)
	assertNoCanary(t, result)
	if result.Outcome != domain.CredentialAccessVerified {
		t.Fatalf("outcome=%s (%s)", result.Outcome, result.Summary)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("expected pre-check then listing, got %d calls", len(runner.calls))
	}
	precheckArgs := append([]string{"-n", "-k", "--"}, ListingArguments(cmsh)...)
	listingArgs := append([]string{"-S", "-k", "-p", SudoPrompt, "--"}, ListingArguments(cmsh)...)
	precheckCall, listingCall := runner.calls[0], runner.calls[1]
	if precheckCall.Path != sudo || strings.Join(precheckCall.Args, "\x00") != strings.Join(precheckArgs, "\x00") {
		t.Fatalf("precheck argv mismatch: %v want %v", precheckCall.Args, precheckArgs)
	}
	for _, arg := range precheckCall.Args {
		if arg == "-l" || arg == "-S" {
			t.Fatalf("the probe must never use -l (listpw is not execution) or -S: %v", precheckCall.Args)
		}
	}
	if listingCall.Path != sudo || strings.Join(listingCall.Args, "\x00") != strings.Join(listingArgs, "\x00") {
		t.Fatalf("listing argv mismatch: %v want %v", listingCall.Args, listingArgs)
	}
	for _, spec := range runner.calls {
		for _, arg := range spec.Args {
			if arg == "-t" || arg == "--tty" {
				t.Fatalf("-t/--tty must never be used: %v", spec.Args)
			}
			if strings.Contains(arg, canary) {
				t.Fatal("password appeared in an argument")
			}
		}
	}
	if len(precheckCall.Stdin) != 0 {
		t.Fatal("the password must never reach the pre-check's stdin")
	}
	if string(listingCall.Stdin) != canary+"\n" {
		t.Fatalf("password must reach sudo through the listing call's stdin exactly once, got %q", listingCall.Stdin)
	}
}

// --- Listing success (documented fixture) ---

func TestCheckVerifiesAccessWithDocumentedJSONFixture(t *testing.T) {
	sudo, cmsh := executables(t)
	runner := &scriptedRunner{t: t, precheck: defaultPrecheck(), listing: CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte(documentedListingJSON), Stderr: []byte(SudoPrompt)}}
	checker := newQualifiedChecker(t, runner, sudo, cmsh)
	fetch, _ := fetchOK([]byte(canary))
	result := checker.Check(context.Background(), samplePlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch)
	assertNoCanary(t, result)
	if result.Outcome != domain.CredentialAccessVerified || result.DevicesListed != 2 || result.BCMVersion != "10.0" {
		t.Fatalf("unexpected result %+v", result)
	}
	var headListed, sudoListing bool
	for _, check := range result.Checks {
		if check.Name == "head_listed" {
			headListed = check.Status == domain.CredentialAccessCheckPassed
		}
		if check.Name == "sudo_listing" {
			sudoListing = check.Status == domain.CredentialAccessCheckPassed
		}
	}
	if !headListed || !sudoListing {
		t.Fatalf("expected head_listed and sudo_listing PASSED: %+v", result.Checks)
	}
}

func TestCheckHeadListedIsNonFatalWhenHeadIsAbsent(t *testing.T) {
	sudo, cmsh := executables(t)
	listingWithoutHead := `[{"type":"PhysicalNode","hostname (key)":"node001","status":"[ UP ]"}]`
	runner := &scriptedRunner{t: t, precheck: defaultPrecheck(), listing: CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte(listingWithoutHead), Stderr: []byte(SudoPrompt)}}
	checker := newQualifiedChecker(t, runner, sudo, cmsh)
	fetch, _ := fetchOK([]byte(canary))
	result := checker.Check(context.Background(), samplePlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch)
	assertNoCanary(t, result)
	if result.Outcome != domain.CredentialAccessVerified {
		t.Fatalf("head_listed failure must not fail the overall outcome, got %s", result.Outcome)
	}
	var found bool
	for _, check := range result.Checks {
		if check.Name == "head_listed" {
			found = true
			if check.Status != domain.CredentialAccessCheckFailed || check.Detail != "head not present in listing" {
				t.Fatalf("unexpected head_listed check: %+v", check)
			}
		}
	}
	if !found {
		t.Fatal("expected a head_listed check")
	}
}

// --- Listing structural failures ---

func TestCheckRejectsUnstructuredJSONListingOutput(t *testing.T) {
	sudo, cmsh := executables(t)
	cases := []struct {
		name    string
		listing CommandOutcome
	}{
		{"error text with exit 0", CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte("ERROR: could not find certificate and key files\n"), Stderr: []byte(SudoPrompt)}},
		{"empty array", CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte("[]"), Stderr: []byte(SudoPrompt)}},
		{"not an array", CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte(`{"type":"HeadNode"}`), Stderr: []byte(SudoPrompt)}},
		{"object missing hostname key", CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte(`[{"type":"HeadNode","status":"[ UP ]"}]`), Stderr: []byte(SudoPrompt)}},
		{"JSON preceded by an event line", CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte("Wed Sep 21 event: node001 changed state\n" + documentedListingJSON), Stderr: []byte(SudoPrompt)}},
		{"truncated stdout", CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte(`[{"type":"HeadNode","hostname (key)":"fixture1`), Stderr: []byte(SudoPrompt), Truncated: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &scriptedRunner{t: t, precheck: defaultPrecheck(), listing: tc.listing}
			checker := newQualifiedChecker(t, runner, sudo, cmsh)
			fetch, _ := fetchOK([]byte(canary))
			result := checker.Check(context.Background(), samplePlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch)
			assertNoCanary(t, result)
			if result.Outcome != domain.CredentialAccessOutputUnexpected {
				t.Fatalf("outcome=%s want %s (%s)", result.Outcome, domain.CredentialAccessOutputUnexpected, result.Summary)
			}
		})
	}
}

// --- Listing authentication failures ---

func TestCheckListingAuthFailureClassification(t *testing.T) {
	sudo, cmsh := executables(t)
	cases := []struct {
		name    string
		listing CommandOutcome
		outcome domain.CredentialAccessOutcome
	}{
		{"wrong password: two prompts + Sorry try again", CommandOutcome{Started: true, ExitCode: 1, Stderr: []byte(SudoPrompt + "Sorry, try again.\n" + SudoPrompt + "sudo: 1 incorrect password attempt " + canary)}, domain.CredentialAccessSudoAuthFailed},
		{"MFA verification code", CommandOutcome{Started: true, ExitCode: 1, Stderr: []byte("Verification code: ")}, domain.CredentialAccessSudoPromptUnexpected},
		{"one prompt plus extra stderr, exit 0", CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte(documentedListingJSON), Stderr: []byte(SudoPrompt + "warning: extra text\n")}, domain.CredentialAccessSudoPromptUnexpected},
		{"zero prompts, exit 0 -> passwordless (should be unreachable, still classified)", CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte(documentedListingJSON)}, domain.CredentialAccessSudoPasswordless},
		{"sudoers denial at listing time", CommandOutcome{Started: true, ExitCode: 1, Stderr: []byte(SudoPrompt + "fixture_user_1 is not in the sudoers file.")}, domain.CredentialAccessSudoPolicyUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &scriptedRunner{t: t, precheck: defaultPrecheck(), listing: tc.listing}
			checker := newQualifiedChecker(t, runner, sudo, cmsh)
			fetch, _ := fetchOK([]byte(canary))
			result := checker.Check(context.Background(), samplePlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch)
			assertNoCanary(t, result)
			if result.Outcome != tc.outcome {
				t.Fatalf("outcome=%s want %s (%s)", result.Outcome, tc.outcome, result.Summary)
			}
		})
	}
}

// --- Timeouts, cancellation, credential unavailability ---

func TestCheckClassifiesTimeoutAndCancellation(t *testing.T) {
	sudo, cmsh := executables(t)

	t.Run("listing timeout", func(t *testing.T) {
		runner := &scriptedRunner{t: t, precheck: defaultPrecheck(), listing: CommandOutcome{Started: true, TimedOut: true, ExitCode: -1}}
		checker := newQualifiedChecker(t, runner, sudo, cmsh)
		fetch, _ := fetchOK([]byte(canary))
		result := checker.Check(context.Background(), samplePlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch)
		assertNoCanary(t, result)
		if result.Outcome != domain.CredentialAccessTimedOut {
			t.Fatalf("outcome=%s want %s", result.Outcome, domain.CredentialAccessTimedOut)
		}
	})

	t.Run("precheck timeout", func(t *testing.T) {
		runner := &scriptedRunner{t: t, precheck: CommandOutcome{Started: true, TimedOut: true, ExitCode: -1}}
		checker := newQualifiedChecker(t, runner, sudo, cmsh)
		fetch, called := fetchOK([]byte(canary))
		result := checker.Check(context.Background(), samplePlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch)
		assertNoCanary(t, result)
		if result.Outcome != domain.CredentialAccessTimedOut {
			t.Fatalf("outcome=%s want %s", result.Outcome, domain.CredentialAccessTimedOut)
		}
		if *called {
			t.Fatal("credential must not be fetched when the pre-check times out")
		}
	})

	t.Run("cancellation during pre-check", func(t *testing.T) {
		runner := &scriptedRunner{t: t, precheck: CommandOutcome{Started: true}}
		checker := newQualifiedChecker(t, runner, sudo, cmsh)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		fetch, called := fetchOK([]byte(canary))
		result := checker.Check(ctx, samplePlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch)
		assertNoCanary(t, result)
		if result.Outcome != domain.CredentialAccessCancelled {
			t.Fatalf("outcome=%s want %s", result.Outcome, domain.CredentialAccessCancelled)
		}
		if *called {
			t.Fatal("credential must not be fetched once the context is cancelled")
		}
	})
}

// TestCheckNeverVerifiesWhenExecutionDidNotTerminateCleanly is the round-3
// review's fixture for finding 2: a runner can hand back an exit 0 and a
// perfectly valid JSON listing while outcome.Err is still set (for example
// exec.ErrWaitDelay, meaning a descendant kept stdout/stderr open past
// WaitDelay). Check must never treat that as verified; it must fail closed
// as INTERNAL, and the summary must not repeat the raw error text.
func TestCheckNeverVerifiesWhenExecutionDidNotTerminateCleanly(t *testing.T) {
	sudo, cmsh := executables(t)

	t.Run("listing outcome.Err set despite clean exit and valid JSON", func(t *testing.T) {
		runner := &scriptedRunner{t: t, precheck: defaultPrecheck(), listing: CommandOutcome{
			Started: true, ExitCode: 0, Stdout: []byte(documentedListingJSON), Stderr: []byte(SudoPrompt), Err: exec.ErrWaitDelay,
		}}
		checker := newQualifiedChecker(t, runner, sudo, cmsh)
		fetch, _ := fetchOK([]byte(canary))
		result := checker.Check(context.Background(), samplePlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch)
		assertNoCanary(t, result)
		if result.Outcome != domain.CredentialAccessInternal {
			t.Fatalf("outcome=%s want %s (%s)", result.Outcome, domain.CredentialAccessInternal, result.Summary)
		}
		if strings.Contains(result.Summary, exec.ErrWaitDelay.Error()) {
			t.Fatalf("summary must not include the raw error text: %q", result.Summary)
		}
	})

	t.Run("precheck outcome.Err set despite a password-required stderr", func(t *testing.T) {
		runner := &scriptedRunner{t: t, precheck: CommandOutcome{
			Started: true, ExitCode: 1, Stderr: []byte("sudo: a password is required\n"), Err: exec.ErrWaitDelay,
		}}
		checker := newQualifiedChecker(t, runner, sudo, cmsh)
		fetch, called := fetchOK([]byte(canary))
		result := checker.Check(context.Background(), samplePlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch)
		assertNoCanary(t, result)
		if result.Outcome != domain.CredentialAccessInternal {
			t.Fatalf("outcome=%s want %s (%s)", result.Outcome, domain.CredentialAccessInternal, result.Summary)
		}
		if *called {
			t.Fatal("credential must not be fetched when the pre-check did not terminate cleanly")
		}
	})
}

func TestCheckClassifiesCredentialFetchFailure(t *testing.T) {
	sudo, cmsh := executables(t)
	runner := &scriptedRunner{t: t, precheck: defaultPrecheck()}
	checker := newQualifiedChecker(t, runner, sudo, cmsh)
	fetch, called := fetchErr(errors.New("control plane refused delivery"))
	result := checker.Check(context.Background(), samplePlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch)
	assertNoCanary(t, result)
	if result.Outcome != domain.CredentialAccessCredentialUnavailable {
		t.Fatalf("outcome=%s want %s", result.Outcome, domain.CredentialAccessCredentialUnavailable)
	}
	if !*called {
		t.Fatal("fetch should have been invoked")
	}
	if len(runner.calls) != 1 {
		t.Fatal("the listing must not run when the credential could not be fetched")
	}
}

// --- Identity checks run before any command or fetch ---

func TestCheckRefusesIdentityMismatchBeforeExecution(t *testing.T) {
	sudo, cmsh := executables(t)
	runner := &scriptedRunner{t: t}
	checker := newQualifiedChecker(t, runner, sudo, cmsh)

	fetch, called := fetchOK([]byte(canary))
	if result := checker.Check(context.Background(), samplePlan("fixture1-zone1-headnode", "root"), 1, fetch); result.Outcome != domain.CredentialAccessLoginMismatch {
		t.Fatalf("login mismatch outcome=%s", result.Outcome)
	}
	if *called {
		t.Fatal("credential must not be fetched on login mismatch")
	}

	fetch2, called2 := fetchOK([]byte(canary))
	if result := checker.Check(context.Background(), samplePlan("other-head", "fixture_user_1"), 1, fetch2); result.Outcome != domain.CredentialAccessHostMismatch {
		t.Fatalf("host mismatch outcome=%s", result.Outcome)
	}
	if *called2 {
		t.Fatal("credential must not be fetched on host mismatch")
	}
	if len(runner.calls) != 0 {
		t.Fatal("no command may run before identity checks pass")
	}

	missing, err := New(Config{SudoPath: "/nonexistent/sudo", CmshPath: cmsh, ReleaseFile: releaseFile(t, observedReleaseFile), ExpectedHost: "fixture1-zone1-headnode", Runner: runner,
		Hostname: func() (string, error) { return "fixture1-zone1-headnode", nil }, CurrentUser: func() (*user.User, error) { return &user.User{Username: "fixture_user_1"}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	fetch3, called3 := fetchOK([]byte(canary))
	if result := missing.Check(context.Background(), samplePlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch3); result.Outcome != domain.CredentialAccessCommandUnavailable {
		t.Fatalf("missing executable outcome=%s", result.Outcome)
	}
	if *called3 {
		t.Fatal("credential must not be fetched when an executable is missing")
	}
}

// --- execRunner: stdin isolation, bounds, and goroutine hygiene ---

func TestExecRunnerDeliversStdinPrivatelyAndEnforcesTimeout(t *testing.T) {
	dir := t.TempDir()
	echo := filepath.Join(dir, "echo-stdin.sh")
	if err := os.WriteFile(echo, []byte("#!/bin/sh\nread line\nprintf 'got:%s' \"$line\"\nprintf 'args:%s' \"$*\" 1>&2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	outcome := execRunner{}.Run(context.Background(), CommandSpec{Path: echo, Args: []string{"-c", "device list"}, Stdin: []byte(canary + "\n"), Timeout: 5 * time.Second, MaxOutputBytes: 1024})
	if !outcome.Started || outcome.ExitCode != 0 || string(outcome.Stdout) != "got:"+canary || strings.Contains(string(outcome.Stderr), canary) {
		t.Fatalf("unexpected exec outcome %+v", outcome)
	}

	// A generously long child sleep with a short timeout: the run must
	// return well before the child would exit on its own, proving the
	// context deadline (not the child) ends the call.
	sleep := filepath.Join(dir, "sleep.sh")
	if err := os.WriteFile(sleep, []byte("#!/bin/sh\nsleep 20\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	slow := execRunner{}.Run(context.Background(), CommandSpec{Path: sleep, Timeout: 1 * time.Second, MaxOutputBytes: 1024})
	if !slow.TimedOut || time.Since(started) > 10*time.Second {
		t.Fatalf("timeout was not enforced: %+v after %s", slow, time.Since(started))
	}

	loud := filepath.Join(dir, "loud.sh")
	if err := os.WriteFile(loud, []byte("#!/bin/sh\nhead -c 5000 /dev/zero | tr '\\0' 'x'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	bounded := execRunner{}.Run(context.Background(), CommandSpec{Path: loud, Timeout: 5 * time.Second, MaxOutputBytes: 100})
	if len(bounded.Stdout) != 100 || !bounded.Truncated {
		t.Fatalf("output bound not enforced: %d bytes, truncated=%v", len(bounded.Stdout), bounded.Truncated)
	}

	// A child that never reads stdin must not block the call: the writer
	// goroutine's pipe write may block forever, but Run itself must still
	// return once the child exits (or the timeout fires), never hanging
	// waiting on the goroutine.
	ignoreStdin := filepath.Join(dir, "ignore-stdin.sh")
	if err := os.WriteFile(ignoreStdin, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	bigStdin := bytes.Repeat([]byte("x"), 1<<20)
	done := make(chan CommandOutcome, 1)
	go func() {
		done <- execRunner{}.Run(context.Background(), CommandSpec{Path: ignoreStdin, Stdin: bigStdin, Timeout: 5 * time.Second, MaxOutputBytes: 1024})
	}()
	select {
	case outcome := <-done:
		if !outcome.Started || outcome.ExitCode != 0 {
			t.Fatalf("unexpected outcome when child ignores stdin: %+v", outcome)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("execRunner blocked when the child never read stdin")
	}

	// A grandchild that keeps stdout open after the parent exits must not
	// keep Run blocked: Setpgid means the group kill on timeout reaches it
	// too, and WaitDelay bounds any residual wait.
	grandchild := filepath.Join(dir, "grandchild.sh")
	if err := os.WriteFile(grandchild, []byte("#!/bin/sh\n(sleep 20 &) \nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	done2 := make(chan CommandOutcome, 1)
	go func() {
		done2 <- execRunner{}.Run(context.Background(), CommandSpec{Path: grandchild, Timeout: 5 * time.Second, MaxOutputBytes: 1024})
	}()
	select {
	case outcome := <-done2:
		if !outcome.Started || outcome.ExitCode != 0 {
			t.Fatalf("unexpected outcome with a detached grandchild: %+v", outcome)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("execRunner blocked on a grandchild holding stdout open")
	}
}

// TestExecRunnerReapsGrandchildProcessGroupAfterWait is the round-3 review's
// real-process fixture for finding 2: a grandchild started in the same
// process group and holding the inherited stdout open must not survive past
// Run returning. The parent exits immediately (so command.Wait itself
// succeeds quickly) but the shell subshell's grandchild keeps stdout open
// long after; the unconditional post-Wait group SIGKILL and reap-poll must
// still reach and remove it within a bounded wait. The required property is
// simply that no descendant is alive once Run has returned — whatever
// outcome.Err ends up being.
func TestExecRunnerReapsGrandchildProcessGroupAfterWait(t *testing.T) {
	dir := t.TempDir()
	grandchild := filepath.Join(dir, "grandchild-pid.sh")
	// The grandchild is redirected from /dev/null so this script (unlike the
	// "(sleep 20 &)" fixture above) does not itself have to wait on it; the
	// parent still exits immediately, leaving the grandchild as the only
	// process left holding the inherited stdout fd open.
	script := "#!/bin/sh\nsleep 60 </dev/null &\necho $!\nexit 0\n"
	if err := os.WriteFile(grandchild, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	outcome := execRunner{}.Run(context.Background(), CommandSpec{Path: grandchild, Timeout: 5 * time.Second, MaxOutputBytes: 1024})
	if !outcome.Started {
		t.Fatalf("command did not start: %+v", outcome)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(outcome.Stdout)))
	if err != nil {
		t.Fatalf("could not parse grandchild pid from stdout %q: %v", outcome.Stdout, err)
	}

	deadline := time.Now().Add(3 * time.Second)
	var gone bool
	for {
		if killErr := syscall.Kill(pid, 0); errors.Is(killErr, syscall.ESRCH) {
			gone = true
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !gone {
		t.Fatalf("grandchild pid %d was still alive after Run returned", pid)
	}
}

// TestExecRunnerStdinWriterGoroutineDoesNotLeak proves the private stdin
// writer goroutine always terminates, even when the child never reads: our
// copy of the pipe's read end is closed right after Start, so once the
// child exits without reading, the write end's Write returns EPIPE and the
// goroutine exits on its own; Run never waits on it directly.
func TestExecRunnerStdinWriterGoroutineDoesNotLeak(t *testing.T) {
	dir := t.TempDir()
	ignoreStdin := filepath.Join(dir, "ignore-stdin.sh")
	if err := os.WriteFile(ignoreStdin, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	baseline := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		bigStdin := bytes.Repeat([]byte("y"), 1<<20)
		outcome := execRunner{}.Run(context.Background(), CommandSpec{Path: ignoreStdin, Stdin: bigStdin, Timeout: 5 * time.Second, MaxOutputBytes: 1024})
		if !outcome.Started || outcome.ExitCode != 0 {
			t.Fatalf("unexpected outcome: %+v", outcome)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	var after int
	for {
		runtime.GC()
		after = runtime.NumGoroutine()
		if after <= baseline+3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if after > baseline+3 {
		t.Fatalf("stdin writer goroutines appear to have leaked: baseline=%d after=%d", baseline, after)
	}
}

// inventoryPlan is samplePlan with the second reviewed operation. Nothing
// else differs: the command, prompt, probe and limits are identical.
func inventoryPlan(host, username string) domain.CredentialAccessTestPlan {
	plan := samplePlan(host, username)
	plan.Operation = domain.CredentialInventoryDiscoveryOperation
	return plan
}

func TestCheckRetainsDeviceRowsOnlyForInventoryDiscovery(t *testing.T) {
	sudo, cmsh := executables(t)
	newRunner := func() *scriptedRunner {
		return &scriptedRunner{t: t, precheck: defaultPrecheck(), listing: CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte(documentedListingJSON), Stderr: []byte(SudoPrompt)}}
	}
	// The identical fake output must retain rows for the discovery and none
	// for the access test.
	accessRunner := newRunner()
	fetch, _ := fetchOK([]byte(canary))
	access := newQualifiedChecker(t, accessRunner, sudo, cmsh).Check(context.Background(), samplePlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch)
	if access.Outcome != domain.CredentialAccessVerified || len(access.Devices) != 0 {
		t.Fatalf("access test retained rows: %+v", access)
	}

	inventoryRunner := newRunner()
	fetch, _ = fetchOK([]byte(canary))
	plan := inventoryPlan("fixture1-zone1-headnode", "fixture_user_1")
	inventory := newQualifiedChecker(t, inventoryRunner, sudo, cmsh).Check(context.Background(), plan, 1, fetch)
	assertNoCanary(t, inventory)
	if inventory.Outcome != domain.CredentialAccessVerified || inventory.DevicesListed != 2 || len(inventory.Devices) != 2 {
		t.Fatalf("inventory result %+v", inventory)
	}
	if inventory.Devices[0] != (domain.CredentialAccessDevice{Type: "HeadNode", Hostname: "fixture1-zone1-headnode", Status: "[ UP ]"}) ||
		inventory.Devices[1] != (domain.CredentialAccessDevice{Type: "PhysicalNode", Hostname: "node001", Status: "[ UP ]"}) {
		t.Fatalf("retained rows %+v", inventory.Devices)
	}
	if err := domain.ValidateCredentialAccessTestResultForPlan(inventory, plan, 1); err != nil {
		t.Fatalf("inventory result failed its own plan binding: %v", err)
	}
	// The two operations differ in exactly one place: the privileged listing
	// command. The secret-free probe is byte-for-byte identical, and so is
	// every other invocation.
	if len(accessRunner.calls) != len(inventoryRunner.calls) || len(accessRunner.calls) != 2 {
		t.Fatalf("call counts differ: %d vs %d", len(accessRunner.calls), len(inventoryRunner.calls))
	}
	if strings.Join(accessRunner.calls[0].Args, "\x00") != strings.Join(inventoryRunner.calls[0].Args, "\x00") {
		t.Fatalf("the secret-free probe argv drifted between operations:\n%v\n%v", accessRunner.calls[0].Args, inventoryRunner.calls[0].Args)
	}
	accessListing := append([]string{"-S", "-k", "-p", SudoPrompt, "--"}, ListingArguments(cmsh)...)
	inventoryListing := append([]string{"-S", "-k", "-p", SudoPrompt, "--"}, InventoryListingArguments(cmsh)...)
	if strings.Join(accessRunner.calls[1].Args, "\x00") != strings.Join(accessListing, "\x00") {
		t.Fatalf("access test listing argv changed: %v", accessRunner.calls[1].Args)
	}
	if strings.Join(inventoryRunner.calls[1].Args, "\x00") != strings.Join(inventoryListing, "\x00") {
		t.Fatalf("discovery listing argv: %v want %v", inventoryRunner.calls[1].Args, inventoryListing)
	}
}

// TestListingArgumentsDifferOnlyByTheReviewedCategoryColumn pins both fixed
// commands. The access test's argv is the one an existing sudoers rule was
// written against, so it must not move; the discovery's argv adds exactly one
// reviewed column and nothing else.
func TestListingArgumentsDifferOnlyByTheReviewedCategoryColumn(t *testing.T) {
	access := ListingArguments("/cm/local/apps/cmd/bin/cmsh")
	inventory := InventoryListingArguments("/cm/local/apps/cmd/bin/cmsh")
	wantAccess := []string{"/cm/local/apps/cmd/bin/cmsh", "--color=no", "--norc", "--noquitconfirmation", "--hide-events", "--quit", "-c", "device; list -f type,hostname,status -d {}"}
	wantInventory := []string{"/cm/local/apps/cmd/bin/cmsh", "--color=no", "--norc", "--noquitconfirmation", "--hide-events", "--quit", "-c", "device; list -f type,hostname,category,status -d {}"}
	if strings.Join(access, "\x00") != strings.Join(wantAccess, "\x00") {
		t.Fatalf("access argv: %v", access)
	}
	if strings.Join(inventory, "\x00") != strings.Join(wantInventory, "\x00") {
		t.Fatalf("discovery argv: %v", inventory)
	}
}

// TestCheckRetainsSanitizedCategoryColumn uses the documented JSON shape with
// the category column the discovery command asks for: a compute category on
// the nodes, no category at all on the head, and an over-long category that is
// truncated rather than refusing the listing.
func TestCheckRetainsSanitizedCategoryColumn(t *testing.T) {
	sudo, cmsh := executables(t)
	longCategory := strings.Repeat("c", domain.CredentialAccessDeviceMaxField+40)
	stdout := `[{"type":"HeadNode","hostname (key)":"fixture1-zone1-headnode","category":"","status":"[   UP   ], health check failed"},` +
		`{"type":"PhysicalNode","hostname (key)":"fixture1-zone1-comp001","category":"asus-h100-compute-category","status":"[   UP   ]"},` +
		`{"type":"PhysicalNode","hostname (key)":"fixture1-zone1-loginnode","category":"login-default-category","status":"[   UP   ]"},` +
		`{"type":"PhysicalNode","hostname (key)":"fixture1-zone1-comp002","category":"` + longCategory + `","status":"[   UP   ]"}]`
	runner := &scriptedRunner{t: t, precheck: defaultPrecheck(), listing: CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte(stdout), Stderr: []byte(SudoPrompt)}}
	fetch, _ := fetchOK([]byte(canary))
	plan := inventoryPlan("fixture1-zone1-headnode", "fixture_user_1")
	result := newQualifiedChecker(t, runner, sudo, cmsh).Check(context.Background(), plan, 1, fetch)
	assertNoCanary(t, result)
	if result.Outcome != domain.CredentialAccessVerified || len(result.Devices) != 4 {
		t.Fatalf("result %+v", result)
	}
	if result.Devices[0].Category != "" || result.Devices[1].Category != "asus-h100-compute-category" || result.Devices[2].Category != "login-default-category" {
		t.Fatalf("categories %+v", result.Devices)
	}
	if len(result.Devices[3].Category) != domain.CredentialAccessDeviceMaxField {
		t.Fatalf("an over-long category must be truncated, not refused: %d", len(result.Devices[3].Category))
	}
	if err := domain.ValidateCredentialAccessTestResultForPlan(result, plan, 1); err != nil {
		t.Fatalf("result failed its own plan binding: %v", err)
	}
	// The access test never asks for the column, so its rows never carry one.
	accessRunner := &scriptedRunner{t: t, precheck: defaultPrecheck(), listing: CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte(stdout), Stderr: []byte(SudoPrompt)}}
	fetch, _ = fetchOK([]byte(canary))
	access := newQualifiedChecker(t, accessRunner, sudo, cmsh).Check(context.Background(), samplePlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch)
	if access.Outcome != domain.CredentialAccessVerified || len(access.Devices) != 0 {
		t.Fatalf("access test retained rows: %+v", access)
	}
}

func TestCheckInventoryDiscoveryRefusesOversizedAndMalformedListings(t *testing.T) {
	sudo, cmsh := executables(t)
	oversized := make([]map[string]string, 0, domain.CredentialAccessTestMaxDevices+1)
	for i := 0; i <= domain.CredentialAccessTestMaxDevices; i++ {
		oversized = append(oversized, map[string]string{"type": "PhysicalNode", "hostname": "node" + strconv.Itoa(i), "status": "[ UP ]"})
	}
	encoded, err := json.Marshal(oversized)
	if err != nil {
		t.Fatal(err)
	}
	longHostname, err := json.Marshal([]map[string]string{{"type": "PhysicalNode", "hostname": strings.Repeat("n", domain.CredentialAccessDeviceMaxField+1), "status": "[ UP ]"}})
	if err != nil {
		t.Fatal(err)
	}
	duplicated := `[{"type":"PhysicalNode","hostname":"node001","status":"[ UP ]"},{"type":"PhysicalNode","hostname":"node001","status":"[ DOWN ]"}]`
	for name, stdout := range map[string]string{
		"over the retained bound": string(encoded),
		"over-long hostname":      string(longHostname),
		"duplicate rows":          duplicated,
	} {
		runner := &scriptedRunner{t: t, precheck: defaultPrecheck(), listing: CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte(stdout), Stderr: []byte(SudoPrompt)}}
		fetch, _ := fetchOK([]byte(canary))
		result := newQualifiedChecker(t, runner, sudo, cmsh).Check(context.Background(), inventoryPlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch)
		if result.Outcome != domain.CredentialAccessOutputUnexpected || len(result.Devices) != 0 {
			t.Fatalf("%s: outcome=%s devices=%d", name, result.Outcome, len(result.Devices))
		}
	}
	// The same oversized listing is still a plain verified access test: the
	// retained bound only constrains what may be kept, not what may be counted.
	runner := &scriptedRunner{t: t, precheck: defaultPrecheck(), listing: CommandOutcome{Started: true, ExitCode: 0, Stdout: encoded, Stderr: []byte(SudoPrompt)}}
	fetch, _ := fetchOK([]byte(canary))
	if result := newQualifiedChecker(t, runner, sudo, cmsh).Check(context.Background(), samplePlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch); result.Outcome != domain.CredentialAccessVerified || len(result.Devices) != 0 {
		t.Fatalf("access test over the retained bound: outcome=%s devices=%d", result.Outcome, len(result.Devices))
	}
}

// TestSanitizeDevicesRefusalReasonsAreContentFree exercises sanitizeDevices
// directly (white-box, same package) for each of the three reachable, fixed
// refusal rules: field_too_long, empty_type_or_hostname and
// duplicate_type_and_hostname. sanitizeRuleUnsanitizedField is not exercised
// here: given SanitizeCredentialAccessText is idempotent (see
// TestSanitizeCredentialAccessTextIsIdempotent in the domain package), the
// per-field re-sanitize check it guards can never observe a mismatch: it is
// kept only as a defensive backstop against that invariant drifting.
func TestSanitizeDevicesRefusalReasonsAreContentFree(t *testing.T) {
	longHostname := strings.Repeat("n", domain.CredentialAccessDeviceMaxField+1)
	tests := []struct {
		name       string
		rows       []domain.CredentialAccessDevice
		wantRule   string
		wantRow    int
		wantType   int
		wantHost   int
		wantStatus int
	}{
		{
			name: "over-long hostname refuses field_too_long at its own row",
			rows: []domain.CredentialAccessDevice{
				{Type: "PhysicalNode", Hostname: "node000", Status: "[ UP ]"},
				{Type: "PhysicalNode", Hostname: longHostname, Status: "[ UP ]"},
			},
			wantRule: sanitizeRuleFieldTooLong, wantRow: 1,
			wantType: len("PhysicalNode"), wantHost: len(longHostname), wantStatus: len("[ UP ]"),
		},
		{
			name: "control-character-only type sanitizes to empty",
			rows: []domain.CredentialAccessDevice{
				{Type: "\x01\x02\x03", Hostname: "node001", Status: "[ UP ]"},
			},
			wantRule: sanitizeRuleEmptyTypeOrHost, wantRow: 0,
			wantType: 3, wantHost: len("node001"), wantStatus: len("[ UP ]"),
		},
		{
			name: "duplicate (type, hostname) pair refuses at the second row",
			rows: []domain.CredentialAccessDevice{
				{Type: "PhysicalNode", Hostname: "node001", Status: "[ UP ]"},
				{Type: "PhysicalNode", Hostname: "node001", Status: "[ DOWN ]"},
			},
			wantRule: sanitizeRuleDuplicate, wantRow: 1,
			wantType: len("PhysicalNode"), wantHost: len("node001"), wantStatus: len("[ DOWN ]"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			retained, refusal := sanitizeDevices(tc.rows)
			if retained != nil {
				t.Fatalf("expected refusal, got retained rows: %+v", retained)
			}
			if refusal == nil {
				t.Fatalf("expected a refusal, got none")
			}
			if refusal.Rule != tc.wantRule {
				t.Fatalf("rule = %q, want %q", refusal.Rule, tc.wantRule)
			}
			if refusal.RowOrdinal != tc.wantRow {
				t.Fatalf("row ordinal = %d, want %d", refusal.RowOrdinal, tc.wantRow)
			}
			if refusal.TypeLen != tc.wantType || refusal.HostLen != tc.wantHost || refusal.StatusLen != tc.wantStatus {
				t.Fatalf("lengths = %d/%d/%d, want %d/%d/%d", refusal.TypeLen, refusal.HostLen, refusal.StatusLen, tc.wantType, tc.wantHost, tc.wantStatus)
			}
			wantSummary := fmt.Sprintf("The listing contained a device row outside the reviewed bounds (row %d, rule %s, lengths %d/%d/%d); no inventory was retained.", tc.wantRow, tc.wantRule, tc.wantType, tc.wantHost, tc.wantStatus)
			if got := refusal.summary(); got != wantSummary {
				t.Fatalf("summary = %q, want %q", got, wantSummary)
			}
			// The summary and detail must never contain any row's raw field
			// text, only the fixed rule name, the row ordinal and lengths.
			for _, row := range tc.rows {
				for _, field := range []string{row.Type, row.Hostname, row.Status} {
					if field != "" && strings.Contains(refusal.summary(), field) {
						t.Fatalf("summary leaked row content %q: %q", field, refusal.summary())
					}
					if field != "" && strings.Contains(refusal.detail(), field) {
						t.Fatalf("detail leaked row content %q: %q", field, refusal.detail())
					}
				}
			}
		})
	}
}

// TestCheckInventoryDiscoveryRefusalSummaryCarriesReasonAndNeverContent runs
// the refusal end-to-end through Check, confirming the fixed reason, row
// ordinal and lengths reach both the check detail and the result summary,
// and that neither ever contains the raw hostname.
func TestCheckInventoryDiscoveryRefusalSummaryCarriesReasonAndNeverContent(t *testing.T) {
	sudo, cmsh := executables(t)
	longHostname := strings.Repeat("n", domain.CredentialAccessDeviceMaxField+1)
	stdout, err := json.Marshal([]map[string]string{
		{"type": "PhysicalNode", "hostname": "node000", "status": "[ UP ]"},
		{"type": "PhysicalNode", "hostname": longHostname, "status": "[ UP ]"},
	})
	if err != nil {
		t.Fatal(err)
	}
	runner := &scriptedRunner{t: t, precheck: defaultPrecheck(), listing: CommandOutcome{Started: true, ExitCode: 0, Stdout: stdout, Stderr: []byte(SudoPrompt)}}
	fetch, _ := fetchOK([]byte(canary))
	result := newQualifiedChecker(t, runner, sudo, cmsh).Check(context.Background(), inventoryPlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch)
	if result.Outcome != domain.CredentialAccessOutputUnexpected || len(result.Devices) != 0 {
		t.Fatalf("result %+v", result)
	}
	wantSummary := fmt.Sprintf("The listing contained a device row outside the reviewed bounds (row 1, rule %s, lengths %d/%d/%d); no inventory was retained.",
		sanitizeRuleFieldTooLong, len("PhysicalNode"), len(longHostname), len("[ UP ]"))
	if result.Summary != wantSummary {
		t.Fatalf("summary = %q, want %q", result.Summary, wantSummary)
	}
	if strings.Contains(result.Summary, longHostname) {
		t.Fatalf("summary leaked the over-long hostname: %q", result.Summary)
	}
	var checkDetail string
	for _, check := range result.Checks {
		if check.Name == "sudo_listing" {
			checkDetail = check.Detail
		}
	}
	if strings.Contains(checkDetail, longHostname) {
		t.Fatalf("check detail leaked the over-long hostname: %q", checkDetail)
	}
	if err := domain.ValidateCredentialAccessTestResultForPlan(result, inventoryPlan("fixture1-zone1-headnode", "fixture_user_1"), 1); err != nil {
		t.Fatalf("refusal result failed its own plan binding: %v", err)
	}
}

// TestCheckInventoryDiscoveryTruncatesOverLongStatusInsteadOfRefusing proves
// the status column is informational, not identity: an over-long raw status
// is truncated to CredentialAccessDeviceMaxField and the listing is still
// retained, unlike an over-long type or hostname.
func TestCheckInventoryDiscoveryTruncatesOverLongStatusInsteadOfRefusing(t *testing.T) {
	sudo, cmsh := executables(t)
	longStatus := strings.Repeat("s", domain.CredentialAccessDeviceMaxField+40)
	stdout, err := json.Marshal([]map[string]string{
		{"type": "PhysicalNode", "hostname": "node001", "status": longStatus},
	})
	if err != nil {
		t.Fatal(err)
	}
	runner := &scriptedRunner{t: t, precheck: defaultPrecheck(), listing: CommandOutcome{Started: true, ExitCode: 0, Stdout: stdout, Stderr: []byte(SudoPrompt)}}
	fetch, _ := fetchOK([]byte(canary))
	plan := inventoryPlan("fixture1-zone1-headnode", "fixture_user_1")
	result := newQualifiedChecker(t, runner, sudo, cmsh).Check(context.Background(), plan, 1, fetch)
	if result.Outcome != domain.CredentialAccessVerified || len(result.Devices) != 1 {
		t.Fatalf("result %+v", result)
	}
	got := result.Devices[0]
	wantStatus := domain.SanitizeCredentialAccessText(longStatus, domain.CredentialAccessDeviceMaxField)
	if got.Type != "PhysicalNode" || got.Hostname != "node001" || got.Status != wantStatus {
		t.Fatalf("retained device %+v, want status %q", got, wantStatus)
	}
	if len(got.Status) != domain.CredentialAccessDeviceMaxField {
		t.Fatalf("truncated status length = %d, want %d", len(got.Status), domain.CredentialAccessDeviceMaxField)
	}
	if err := domain.ValidateCredentialAccessTestResultForPlan(result, plan, 1); err != nil {
		t.Fatalf("truncated-status result failed its own plan binding: %v", err)
	}
}

func TestParseListingAcceptsDocumentedKeyVariantsAndOptionalStatus(t *testing.T) {
	for name, stdout := range map[string]string{
		"documented key spelling": `[{"type":"PhysicalNode","hostname (key)":"node001","status":"[ UP ]"}]`,
		"plain keys":              `[{"type":"PhysicalNode","hostname":"node001","status":"[ UP ]"}]`,
		"mixed case keys":         `[{"Type":"PhysicalNode","Hostname (key)":"node001","Status":"[ UP ]"}]`,
	} {
		rows, devices, headListed, structured := parseListing(stdout, "node001")
		if !structured || devices != 1 || !headListed || len(rows) != 1 || rows[0].Hostname != "node001" || rows[0].Type != "PhysicalNode" || rows[0].Status != "[ UP ]" {
			t.Fatalf("%s: rows=%+v devices=%d structured=%v", name, rows, devices, structured)
		}
	}
	// The status column is optional; its absence is not an error and leaves
	// the retained field empty rather than failing the listing.
	rows, devices, _, structured := parseListing(`[{"type":"PhysicalNode","hostname":"node001"}]`, "node001")
	if !structured || devices != 1 || len(rows) != 1 || rows[0].Status != "" {
		t.Fatalf("optional status: rows=%+v devices=%d structured=%v", rows, devices, structured)
	}
	// A malformed row still fails the whole listing and retains nothing.
	for name, stdout := range map[string]string{
		"missing hostname": `[{"type":"PhysicalNode"}]`,
		"empty type":       `[{"type":"","hostname":"node001"}]`,
		"non-string type":  `[{"type":7,"hostname":"node001"}]`,
		"not an array":     `{"type":"PhysicalNode","hostname":"node001"}`,
	} {
		if rows, devices, _, structured := parseListing(stdout, "node001"); structured || devices != 0 || len(rows) != 0 {
			t.Fatalf("%s accepted: rows=%+v devices=%d structured=%v", name, rows, devices, structured)
		}
	}
}

// TestCheckInventoryDiscoveryTruncationReportsTheRetainedBound proves the two
// bounds a discovery can hit read as one limit. MaxOutputBytes (64 KiB by
// plan) cuts the JSON off long before 512 rows have been printed, so a large
// listing reaches the output bound first; reporting that as a byte limit
// would leave the operator unable to relate it to the row limit they were
// told about. The access test's own truncation message is unchanged.
func TestCheckInventoryDiscoveryTruncationReportsTheRetainedBound(t *testing.T) {
	sudo, cmsh := executables(t)
	truncated := CommandOutcome{Started: true, ExitCode: 0, Stdout: []byte(documentedListingJSON), Stderr: []byte(SudoPrompt), Truncated: true}

	runner := &scriptedRunner{t: t, precheck: defaultPrecheck(), listing: truncated}
	fetch, _ := fetchOK([]byte(canary))
	result := newQualifiedChecker(t, runner, sudo, cmsh).Check(context.Background(), inventoryPlan("fixture1-zone1-headnode", "fixture_user_1"), 1, fetch)
	if result.Outcome != domain.CredentialAccessOutputUnexpected || len(result.Devices) != 0 {
		t.Fatalf("outcome=%s devices=%d", result.Outcome, len(result.Devices))
	}
	var detail string
	for _, check := range result.Checks {
		if check.Name == "sudo_listing" {
			detail = check.Detail
		}
	}
	if detail != retainedBoundDetail {
		t.Fatalf("truncated discovery detail %q, want %q", detail, retainedBoundDetail)
	}
	if result.Summary != retainedBoundSummary {
		t.Fatalf("truncated discovery summary %q", result.Summary)
	}
	assertNoCanary(t, result)

	// The row-count refusal reports the identical text, so an operator sees
	// one coherent limit whichever bound the listing actually hit.
	oversized := make([]map[string]string, 0, domain.CredentialAccessTestMaxDevices+1)
	for i := 0; i <= domain.CredentialAccessTestMaxDevices; i++ {
		oversized = append(oversized, map[string]string{"type": "PhysicalNode", "hostname": "node" + strconv.Itoa(i), "status": "[ UP ]"})
	}
	encoded, err := json.Marshal(oversized)
	if err != nil {
		t.Fatal(err)
	}
	overRunner := &scriptedRunner{t: t, precheck: defaultPrecheck(), listing: CommandOutcome{Started: true, ExitCode: 0, Stdout: encoded, Stderr: []byte(SudoPrompt)}}
	overFetch, _ := fetchOK([]byte(canary))
	overResult := newQualifiedChecker(t, overRunner, sudo, cmsh).Check(context.Background(), inventoryPlan("fixture1-zone1-headnode", "fixture_user_1"), 1, overFetch)
	if overResult.Summary != retainedBoundSummary {
		t.Fatalf("row-bound summary %q does not match the truncation summary", overResult.Summary)
	}

	// The access test is untouched: it retains nothing, so a truncated
	// listing is still reported as the output bound it actually hit.
	accessRunner := &scriptedRunner{t: t, precheck: defaultPrecheck(), listing: truncated}
	accessFetch, _ := fetchOK([]byte(canary))
	access := newQualifiedChecker(t, accessRunner, sudo, cmsh).Check(context.Background(), samplePlan("fixture1-zone1-headnode", "fixture_user_1"), 1, accessFetch)
	if access.Outcome != domain.CredentialAccessOutputUnexpected {
		t.Fatalf("access test truncation outcome=%s", access.Outcome)
	}
	if access.Summary == retainedBoundSummary {
		t.Fatal("the access test adopted the discovery's retained-bound message")
	}
}
