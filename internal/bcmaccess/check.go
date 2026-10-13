// Package bcmaccess runs the fixed, reviewed, read-only BCM access check on
// the head. It never accepts shell text or model-authored arguments: the
// only inputs are the secret-free plan, a locally configured executable pair,
// and a sudo password that is fetched only after every unprivileged and
// passwordless pre-check has passed, written to a private stdin pipe, and
// cleared.
package bcmaccess

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	// SudoPrompt is the fixed prompt string. sudo echoes it once per password
	// request; stdin closes after one line, so a second request or any other
	// prompt text is an explicit unsupported-authentication outcome.
	SudoPrompt = "SHERLOCK_SUDO_PASSWORD:"

	// listingCommand is the only BCM command the access test executes, always
	// requested as JSON output (see "Creating JSON Format Output From A
	// Table Format Output In cmsh" in the admin manual).
	listingCommand = `device; list -f type,hostname,status -d {}`

	// inventoryListingCommand is the second fixed command, used by the
	// inventory discovery operation alone. It differs from listingCommand by
	// exactly one additional reviewed column: the BCM device category, which
	// is the head's own grouping of nodes and is the evidence a preview needs
	// to tell a GPU compute node apart from a login or service node. It is
	// still a fixed constant: no column, argument or command text is ever
	// derived from the plan, the operator or a model.
	inventoryListingCommand = `device; list -f type,hostname,category,status -d {}`

	DefaultSudoPath    = "/usr/bin/sudo"
	DefaultCmshPath    = "/cm/local/apps/cmd/bin/cmsh"
	DefaultReleaseFile = "/etc/cm-release"

	maxPasswordBytes    = 8 << 10
	maxReleaseFileBytes = 4 << 10
	redactedMarker      = "[REDACTED]"

	// retainedBoundDetail and retainedBoundSummary are the one fixed text a
	// discovery reports when the listing is larger than what may be kept,
	// whether the output bound truncated it or the row count exceeded the
	// reviewed maximum. Neither carries any host output.
	retainedBoundDetail  = "listing exceeds the retained bound"
	retainedBoundSummary = "The listing exceeds the reviewed retained bound; no inventory was retained."
)

var (
	// releaseLinePattern matches the first line of /etc/cm-release exactly
	// (per §11.1.2 of the admin manual). A trailing \r is tolerated and
	// stripped before matching; anything else — extra leading text, a
	// different product string, missing digits — fails closed.
	releaseLinePattern = regexp.MustCompile(`^Cluster Manager v(\d{1,3})\.(\d{1,3})$`)
	// supportedBCMMajors is the reviewed, qualified major-version set. Only
	// BCM 10 has been qualified against the reviewed cmsh JSON listing shape.
	supportedBCMMajors = map[string]bool{"10": true}

	sudoTryAgainPattern     = regexp.MustCompile(`(?i)sorry, try again|incorrect password|authentication failure|no password was provided`)
	sudoPolicyPattern       = regexp.MustCompile(`(?i)is not in the sudoers|not allowed to execute|may not run sudo|a terminal is required|no tty present|sudo: unable to`)
	passwordRequiredPattern = regexp.MustCompile(`(?i)a password is required`)
)

// errDescendantsAlive means the child's process group was still non-empty
// (or the private stdin writer goroutine had not exited) after WaitDelay
// past command.Wait returning. A run in this state is never trusted, even
// if the captured exit code and output otherwise look clean: something in
// the process tree may still hold stdout/stderr open, or be running with
// access to the same environment, past the point Check believes the
// command finished. A descendant that escaped the process group (for
// example via setsid) cannot be reached by the group SIGKILL below; that
// case is instead caught by exec.ErrWaitDelay from command.Wait itself.
var errDescendantsAlive = errors.New("descendant process or stdin writer remained after WaitDelay")

// CommandSpec is one fixed invocation. Stdin is the private password pipe
// contents; it is never placed in Args or Env.
type CommandSpec struct {
	Path           string
	Args           []string
	Stdin          []byte
	Timeout        time.Duration
	MaxOutputBytes int64
}

// CommandOutcome is a bounded capture of one invocation.
type CommandOutcome struct {
	Started   bool
	ExitCode  int
	Stdout    []byte
	Stderr    []byte
	TimedOut  bool
	Truncated bool
	Err       error
}

// Runner executes fixed commands. Production uses execRunner; tests supply
// scripted fixtures so no sudo or BCM binary is needed.
type Runner interface {
	Run(context.Context, CommandSpec) CommandOutcome
}

// Config binds the head to one expected identity and executable pair.
type Config struct {
	SudoPath     string
	CmshPath     string
	ReleaseFile  string
	ExpectedHost string
	Runner       Runner
	// Hostname and CurrentUser are overridable for fixtures.
	Hostname    func() (string, error)
	CurrentUser func() (*user.User, error)
	Now         func() time.Time
}

// Checker executes the contract for one plan.
type Checker struct {
	cfg Config
}

func New(cfg Config) (*Checker, error) {
	if cfg.SudoPath == "" {
		cfg.SudoPath = DefaultSudoPath
	}
	if cfg.CmshPath == "" {
		cfg.CmshPath = DefaultCmshPath
	}
	if cfg.ReleaseFile == "" {
		cfg.ReleaseFile = DefaultReleaseFile
	}
	if !strings.HasPrefix(cfg.SudoPath, "/") || !strings.HasPrefix(cfg.CmshPath, "/") || !strings.HasPrefix(cfg.ReleaseFile, "/") ||
		strings.ContainsAny(cfg.SudoPath+cfg.CmshPath+cfg.ReleaseFile, " \t\r\n\x00") {
		return nil, errors.New("bcm access check paths must be absolute")
	}
	if strings.TrimSpace(cfg.ExpectedHost) == "" || len(cfg.ExpectedHost) > 256 {
		return nil, errors.New("bcm access check requires the expected head host name")
	}
	if cfg.Runner == nil {
		cfg.Runner = execRunner{}
	}
	if cfg.Hostname == nil {
		cfg.Hostname = os.Hostname
	}
	if cfg.CurrentUser == nil {
		cfg.CurrentUser = user.Current
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Checker{cfg: cfg}, nil
}

// ListingArguments is the fixed, reviewed cmsh invocation used for the
// unprivileged sudo policy pre-check of every operation and for the
// privileged access-test listing, so the two can never drift apart. It never
// receives plan-derived or operator-derived text.
//
// The pre-check deliberately keeps this argv for the inventory discovery too.
// It is the secret-free probe of one sudoers rule, and the reviewed sudoers
// entry authorizes the cmsh binary with its fixed flags; probing with a
// second, longer command would test a different string without proving
// anything more about the policy.
func ListingArguments(cmshPath string) []string {
	return cmshArguments(cmshPath, listingCommand)
}

// InventoryListingArguments is the fixed, reviewed cmsh invocation the
// inventory discovery operation runs. It is identical to ListingArguments
// except for the one extra reviewed column in the fixed command text.
func InventoryListingArguments(cmshPath string) []string {
	return cmshArguments(cmshPath, inventoryListingCommand)
}

func cmshArguments(cmshPath, command string) []string {
	return []string{cmshPath, "--color=no", "--norc", "--noquitconfirmation", "--hide-events", "--quit", "-c", command}
}

// listingArgumentsFor selects the reviewed argv by operation. It is the only
// place the operation influences what is executed, and the mapping is a
// closed switch over the two reviewed operations: an unknown operation falls
// back to the narrower access-test command rather than inventing one.
func listingArgumentsFor(operation, cmshPath string) []string {
	if operation == domain.CredentialInventoryDiscoveryOperation {
		return InventoryListingArguments(cmshPath)
	}
	return ListingArguments(cmshPath)
}

// Check runs the contract. The password is fetched only after identity,
// executables, version and sudo policy have all passed; it is copied once,
// used once, and both the copy and the caller's returned slice are cleared
// before Check returns.
func (checker *Checker) Check(ctx context.Context, plan domain.CredentialAccessTestPlan, attempt int, fetch func(context.Context) ([]byte, error)) domain.CredentialAccessTestResult {
	started := checker.cfg.Now()
	result := domain.CredentialAccessTestResult{SchemaVersion: domain.CredentialAccessTestSchemaVersion, TestID: plan.TestID, Attempt: attempt, StartedAt: started}
	digest, err := domain.CredentialAccessTestPlanDigest(plan)
	if err != nil {
		return checker.finish(result, domain.CredentialAccessInternal, "The plan failed local validation before execution.")
	}
	result.PlanDigest = digest.String()

	// Identity: never switch users or hosts to satisfy a plan.
	current, err := checker.cfg.CurrentUser()
	if err != nil || current == nil || current.Username != plan.Username {
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "login_identity", Status: domain.CredentialAccessCheckFailed, Detail: "The collector's login user does not match the credential username."})
		return checker.finish(result, domain.CredentialAccessLoginMismatch, "The head collector does not run as the credential's login user; it will not switch users.")
	}
	result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "login_identity", Status: domain.CredentialAccessCheckPassed})

	hostname, err := checker.cfg.Hostname()
	if err != nil || !hostMatches(hostname, checker.cfg.ExpectedHost) || !hostMatches(plan.Host, checker.cfg.ExpectedHost) {
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "head_host", Status: domain.CredentialAccessCheckFailed, Detail: "The plan host does not match this head's configured identity."})
		return checker.finish(result, domain.CredentialAccessHostMismatch, "The credential's host does not match the head that received the test.")
	}
	result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "head_host", Status: domain.CredentialAccessCheckPassed})

	for _, path := range []string{checker.cfg.SudoPath, checker.cfg.CmshPath} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "executables", Status: domain.CredentialAccessCheckFailed, Detail: "A required executable is missing or not executable on the head."})
			return checker.finish(result, domain.CredentialAccessCommandUnavailable, "sudo or cmsh is not available at the configured path on the head.")
		}
	}
	result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "executables", Status: domain.CredentialAccessCheckPassed})

	// Version: an unprivileged read of the release file. No command is run.
	bcmVersion, versionDetail, versionOK := checker.detectVersion()
	result.BCMVersion = bcmVersion
	if !versionOK {
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "bcm_version", Status: domain.CredentialAccessCheckFailed, Detail: versionDetail})
		return checker.finish(result, domain.CredentialAccessVersionUnsupported, "The release file did not report a reviewed BCM major version; nothing further was executed.")
	}
	result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "bcm_version", Status: domain.CredentialAccessCheckPassed, Detail: "BCM " + bcmVersion})

	timeout := time.Duration(plan.Limits.TimeoutSeconds) * time.Second

	// Sudo policy and passwordless pre-check: never sends a secret, and never
	// uses "sudo -l" (listing authentication is governed by the sudoers
	// listpw option and does not prove passwordless *execution*; see the
	// round-3 review). Instead this executes the exact reviewed command with
	// -n so sudo either runs it without a password or reports that a
	// password is required, and no stdin is attached.
	precheckArgs := append([]string{"-n", "-k", "--"}, ListingArguments(checker.cfg.CmshPath)...)
	precheck := checker.cfg.Runner.Run(ctx, CommandSpec{Path: checker.cfg.SudoPath, Args: precheckArgs, Timeout: timeout, MaxOutputBytes: plan.Limits.MaxOutputBytes})
	if outcome, ok := classifyInterruption(ctx, precheck); ok {
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_policy", Status: domain.CredentialAccessCheckFailed})
		return checker.finish(result, outcome, "The sudo policy pre-check did not complete.")
	}
	if !precheck.Started {
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_policy", Status: domain.CredentialAccessCheckFailed, Detail: "sudo could not be started on the head."})
		return checker.finish(result, domain.CredentialAccessCommandUnavailable, "sudo could not be started on the head.")
	}
	if precheck.Err != nil {
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_policy", Status: domain.CredentialAccessCheckFailed, Detail: "execution did not terminate cleanly"})
		return checker.finish(result, domain.CredentialAccessInternal, "execution did not terminate cleanly")
	}
	precheckStderr := string(precheck.Stderr)
	switch {
	case precheck.ExitCode == 0:
		// sudo actually executed the reviewed command with no password. This
		// is only trusted as passwordless once the stdout is validated with
		// the same JSON listing parser used for the real listing; anything
		// else means sudo ran something but the output cannot be trusted,
		// which stops before any credential is fetched either way.
		_, devices, _, structured := parseListing(string(precheck.Stdout), plan.Host)
		if structured && devices > 0 && !precheck.Truncated && strings.TrimSpace(precheckStderr) == "" {
			if plan.Purpose == domain.CredentialAccessPasswordlessPurpose {
				result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_policy", Status: domain.CredentialAccessCheckPassed, Detail: "the reviewed command ran without a password"})
				listing := precheck
				if plan.Operation == domain.CredentialInventoryDiscoveryOperation {
					listing = checker.cfg.Runner.Run(ctx, CommandSpec{Path: checker.cfg.SudoPath, Args: append([]string{"-n", "-k", "--"}, InventoryListingArguments(checker.cfg.CmshPath)...), Timeout: timeout, MaxOutputBytes: plan.Limits.MaxOutputBytes})
				}
				return checker.finishPasswordlessListing(ctx, result, plan, listing)
			}
			result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_policy", Status: domain.CredentialAccessCheckFailed, Detail: "sudo ran the reviewed command without requesting a password."})
			return checker.finish(result, domain.CredentialAccessSudoPasswordless, "sudo is passwordless for this command: the read-only listing succeeded without the stored password, so the stored credential was NOT verified.")
		}
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_policy", Status: domain.CredentialAccessCheckFailed, Detail: "sudo ran the reviewed command without a password but the output did not match the reviewed listing."})
		return checker.finish(result, domain.CredentialAccessOutputUnexpected, "sudo ran the reviewed command without a password, but the output was not a recognizable device listing; nothing further was executed.")
	case passwordRequiredPattern.MatchString(precheckStderr):
		if plan.Purpose == domain.CredentialAccessPasswordlessPurpose {
			result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_policy", Status: domain.CredentialAccessCheckFailed, Detail: "the reviewed command requires a password"})
			return checker.finish(result, domain.CredentialAccessSudoAuthFailed, "This authorization requires passwordless sudo, but the reviewed command requested a password.")
		}
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_policy", Status: domain.CredentialAccessCheckPassed})
	case sudoPolicyPattern.MatchString(precheckStderr):
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_policy", Status: domain.CredentialAccessCheckFailed, Detail: "sudo policy refused the reviewed command."})
		return checker.finish(result, domain.CredentialAccessSudoPolicyUnsupported, "sudo policy does not permit this user to run the reviewed cmsh listing.")
	default:
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_policy", Status: domain.CredentialAccessCheckFailed, Detail: "sudo emitted an unexpected response to the policy pre-check."})
		return checker.finish(result, domain.CredentialAccessSudoPromptUnexpected, "sudo emitted an unexpected response before any credential was used; authentication was not attempted.")
	}

	// Only now, after every unprivileged and passwordless check has passed,
	// is the credential fetched.
	sudoPassword, err := fetch(ctx)
	if err != nil {
		return checker.finish(result, domain.CredentialAccessCredentialUnavailable, "The control plane did not deliver the credential for this attempt; nothing was executed.")
	}
	if len(sudoPassword) == 0 || len(sudoPassword) > maxPasswordBytes || bytes.ContainsAny(sudoPassword, "\r\n\x00") {
		clear(sudoPassword)
		return checker.finish(result, domain.CredentialAccessCredentialUnavailable, "The delivered credential was empty or malformed; nothing was executed.")
	}
	password := append([]byte(nil), sudoPassword...)
	password = append(password, '\n')
	defer clear(password)
	defer clear(sudoPassword)

	listingArgs := append([]string{"-S", "-k", "-p", SudoPrompt, "--"}, listingArgumentsFor(plan.Operation, checker.cfg.CmshPath)...)
	listing := checker.cfg.Runner.Run(ctx, CommandSpec{
		Path: checker.cfg.SudoPath, Args: listingArgs,
		Stdin: password, Timeout: timeout, MaxOutputBytes: plan.Limits.MaxOutputBytes,
	})
	stdout := redact(listing.Stdout, sudoPassword)
	stderr := redact(listing.Stderr, sudoPassword)
	if outcome, ok := classifyInterruption(ctx, listing); ok {
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_listing", Status: domain.CredentialAccessCheckFailed})
		return checker.finish(result, outcome, "The privileged listing did not complete within its limits.")
	}
	prompts := strings.Count(stderr, SudoPrompt)
	other := strings.TrimSpace(strings.ReplaceAll(stderr, SudoPrompt, ""))
	if !listing.Started {
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_listing", Status: domain.CredentialAccessCheckFailed})
		return checker.finish(result, domain.CredentialAccessCommandUnavailable, "sudo could not be started on the head.")
	}
	if listing.Err != nil {
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_listing", Status: domain.CredentialAccessCheckFailed, Detail: "execution did not terminate cleanly"})
		return checker.finish(result, domain.CredentialAccessInternal, "execution did not terminate cleanly")
	}
	if listing.Truncated {
		// The two bounds a discovery can hit are one limit to the operator:
		// MaxOutputBytes cuts the JSON off long before 512 device rows have
		// been printed, so a large listing reaches the output bound first and
		// never reaches the retained-row bound. Both are therefore reported
		// with the same fixed text, rather than as a byte limit the operator
		// has no way to relate to the row limit they were told about.
		if plan.Operation == domain.CredentialInventoryDiscoveryOperation {
			result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_listing", Status: domain.CredentialAccessCheckFailed, Detail: retainedBoundDetail})
			return checker.finish(result, domain.CredentialAccessOutputUnexpected, retainedBoundSummary)
		}
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_listing", Status: domain.CredentialAccessCheckFailed, Detail: "output exceeded its bound"})
		return checker.finish(result, domain.CredentialAccessOutputUnexpected, "The listing output exceeded its bound and was truncated; the result is not trusted.")
	}
	if listing.ExitCode != 0 {
		switch {
		case sudoPolicyPattern.MatchString(other):
			result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_listing", Status: domain.CredentialAccessCheckFailed, Detail: "sudo policy refused the reviewed command."})
			return checker.finish(result, domain.CredentialAccessSudoPolicyUnsupported, "sudo policy does not permit this user to run the reviewed cmsh listing.")
		case prompts > 1 || sudoTryAgainPattern.MatchString(other):
			result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_listing", Status: domain.CredentialAccessCheckFailed, Detail: "sudo rejected the supplied password."})
			return checker.finish(result, domain.CredentialAccessSudoAuthFailed, "sudo rejected the stored password; the credential is not valid for this head.")
		case prompts == 0 && other != "":
			result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_listing", Status: domain.CredentialAccessCheckFailed, Detail: "sudo emitted an unexpected prompt or message."})
			return checker.finish(result, domain.CredentialAccessSudoPromptUnexpected, "sudo asked for something other than the reviewed password prompt (for example MFA); authentication was not bypassed.")
		default:
			result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_listing", Status: domain.CredentialAccessCheckFailed, Detail: "cmsh exited with a non-zero status."})
			return checker.finish(result, domain.CredentialAccessOutputUnexpected, "cmsh accepted sudo but the listing exited with an error.")
		}
	}
	// Success requires the reviewed sequence exactly: exit 0, exactly one
	// SudoPrompt occurrence on stderr and no other non-whitespace stderr
	// text. Zero prompts with exit 0 means sudo never asked for the stored
	// password; this should be unreachable after the policy pre-check but is
	// still classified explicitly rather than trusted.
	switch {
	case prompts == 0:
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_listing", Status: domain.CredentialAccessCheckFailed, Detail: "sudo did not request a password."})
		return checker.finish(result, domain.CredentialAccessSudoPasswordless, "sudo did not request a password, so the stored credential was NOT verified; sudo access appears passwordless or pre-cached for this user.")
	case prompts > 1 || other != "":
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_listing", Status: domain.CredentialAccessCheckFailed, Detail: "sudo emitted unexpected prompt text."})
		return checker.finish(result, domain.CredentialAccessSudoPromptUnexpected, "sudo emitted an unexpected prompt sequence; the result is not trusted.")
	}
	rows, devices, headListed, structured := parseListing(stdout, plan.Host)
	if !structured || devices == 0 {
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_listing", Status: domain.CredentialAccessCheckFailed, Detail: "The listing did not match the reviewed JSON device listing structure."})
		return checker.finish(result, domain.CredentialAccessOutputUnexpected, "The listing succeeded but did not return a recognizable device listing.")
	}
	// Rows are retained only for the operation that was authorized to keep
	// them. For bcm.access_test.v1 the behaviour below is byte-for-byte what
	// it was before this operation existed.
	if plan.Operation == domain.CredentialInventoryDiscoveryOperation {
		if devices > domain.CredentialAccessTestMaxDevices {
			result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_listing", Status: domain.CredentialAccessCheckFailed, Detail: retainedBoundDetail})
			return checker.finish(result, domain.CredentialAccessOutputUnexpected, retainedBoundSummary)
		}
		retained, refusal := sanitizeDevices(rows)
		if refusal != nil {
			result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_listing", Status: domain.CredentialAccessCheckFailed, Detail: refusal.detail()})
			return checker.finish(result, domain.CredentialAccessOutputUnexpected, refusal.summary())
		}
		result.Devices = retained
	}
	result.DevicesListed = devices
	result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_listing", Status: domain.CredentialAccessCheckPassed, Detail: fmt.Sprintf("%d device rows", devices)})
	if headListed {
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "head_listed", Status: domain.CredentialAccessCheckPassed})
	} else {
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "head_listed", Status: domain.CredentialAccessCheckFailed, Detail: "head not present in listing"})
	}
	if plan.Operation == domain.CredentialInventoryDiscoveryOperation {
		return checker.finish(result, domain.CredentialAccessVerified, fmt.Sprintf("cmsh listed %d devices read-only on BCM %s and the inventory rows were retained.", devices, bcmVersion))
	}
	return checker.finish(result, domain.CredentialAccessVerified, fmt.Sprintf("sudo authenticated and cmsh listed %d devices read-only on BCM %s.", devices, bcmVersion))
}

// finishPasswordlessListing records read-only BCM access without claiming that
// any stored password was authenticated. No credential is fetched in this mode.
func (checker *Checker) finishPasswordlessListing(ctx context.Context, result domain.CredentialAccessTestResult, plan domain.CredentialAccessTestPlan, listing CommandOutcome) domain.CredentialAccessTestResult {
	failed := func(outcome domain.CredentialAccessOutcome, detail, summary string) domain.CredentialAccessTestResult {
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_listing", Status: domain.CredentialAccessCheckFailed, Detail: detail})
		return checker.finish(result, outcome, summary)
	}
	if outcome, interrupted := classifyInterruption(ctx, listing); interrupted {
		return failed(outcome, "listing interrupted", "The passwordless BCM listing did not complete.")
	}
	if !listing.Started {
		return failed(domain.CredentialAccessCommandUnavailable, "sudo could not start", "sudo could not start on the head.")
	}
	if listing.Err != nil {
		return failed(domain.CredentialAccessInternal, "execution did not terminate cleanly", "The BCM listing did not terminate cleanly.")
	}
	if listing.Truncated {
		return failed(domain.CredentialAccessOutputUnexpected, retainedBoundDetail, retainedBoundSummary)
	}
	if listing.ExitCode != 0 {
		if passwordRequiredPattern.Match(listing.Stderr) {
			return failed(domain.CredentialAccessSudoAuthFailed, "the listing requires a password", "The reviewed listing requires a password.")
		}
		return failed(domain.CredentialAccessSudoPolicyUnsupported, "the listing did not succeed", "sudo did not permit the reviewed passwordless listing.")
	}
	if strings.TrimSpace(string(listing.Stderr)) != "" {
		return failed(domain.CredentialAccessSudoPromptUnexpected, "unexpected stderr", "The listing emitted unexpected text on stderr.")
	}
	rows, devices, headListed, structured := parseListing(string(listing.Stdout), plan.Host)
	if !structured || devices == 0 {
		return failed(domain.CredentialAccessOutputUnexpected, "unrecognized listing", "The listing did not match the reviewed BCM JSON structure.")
	}
	if plan.Operation == domain.CredentialInventoryDiscoveryOperation {
		if devices > domain.CredentialAccessTestMaxDevices {
			return failed(domain.CredentialAccessOutputUnexpected, retainedBoundDetail, retainedBoundSummary)
		}
		retained, refusal := sanitizeDevices(rows)
		if refusal != nil {
			return failed(domain.CredentialAccessOutputUnexpected, refusal.detail(), refusal.summary())
		}
		result.Devices = retained
	}
	result.DevicesListed = devices
	result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "sudo_listing", Status: domain.CredentialAccessCheckPassed, Detail: fmt.Sprintf("%d device rows", devices)})
	if headListed {
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "head_listed", Status: domain.CredentialAccessCheckPassed})
	} else {
		result.Checks = append(result.Checks, domain.CredentialAccessCheck{Name: "head_listed", Status: domain.CredentialAccessCheckFailed, Detail: "head not present in listing"})
	}
	return checker.finish(result, domain.CredentialAccessPasswordlessVerified, fmt.Sprintf("Passwordless sudo ran the reviewed read-only BCM listing of %d devices; no stored password was used.", devices))
}

// detectVersion reads at most 4 KiB from the configured release file
// unprivileged. Only the first line is inspected; it must match exactly
// (a trailing \r is tolerated). No file content is ever placed in a check
// detail or summary.
func (checker *Checker) detectVersion() (version string, detail string, ok bool) {
	file, err := os.Open(checker.cfg.ReleaseFile)
	if err != nil {
		return "", "the release file could not be opened", false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", "the release file is not a regular file", false
	}
	data, err := io.ReadAll(io.LimitReader(file, maxReleaseFileBytes))
	if err != nil {
		return "", "the release file could not be read", false
	}
	first, _, _ := strings.Cut(string(data), "\n")
	first = strings.TrimSuffix(first, "\r")
	match := releaseLinePattern.FindStringSubmatch(first)
	if match == nil {
		return "", "the release file did not match the reviewed version line format", false
	}
	major, minor := match[1], match[2]
	version = major + "." + minor
	if !supportedBCMMajors[major] {
		return version, "the release file reported a BCM major version that is not reviewed", false
	}
	return version, "", true
}

func (checker *Checker) finish(result domain.CredentialAccessTestResult, outcome domain.CredentialAccessOutcome, summary string) domain.CredentialAccessTestResult {
	result.Outcome = outcome
	result.Summary = domain.SanitizeCredentialAccessText(summary, domain.CredentialAccessTestMaxSummary)
	result.BCMVersion = domain.SanitizeCredentialAccessText(result.BCMVersion, domain.CredentialAccessTestMaxVersion)
	for i := range result.Checks {
		result.Checks[i].Detail = domain.SanitizeCredentialAccessText(result.Checks[i].Detail, domain.CredentialAccessTestMaxSummary)
	}
	result.CompletedAt = checker.cfg.Now()
	if result.CompletedAt.Before(result.StartedAt) {
		result.CompletedAt = result.StartedAt
	}
	return result
}

func classifyInterruption(ctx context.Context, outcome CommandOutcome) (domain.CredentialAccessOutcome, bool) {
	if ctx.Err() != nil {
		return domain.CredentialAccessCancelled, true
	}
	if outcome.TimedOut {
		return domain.CredentialAccessTimedOut, true
	}
	return "", false
}

func hostMatches(actual, expected string) bool {
	actual, expected = strings.ToLower(strings.TrimSpace(actual)), strings.ToLower(strings.TrimSpace(expected))
	if actual == "" || expected == "" {
		return false
	}
	return actual == expected || strings.SplitN(actual, ".", 2)[0] == strings.SplitN(expected, ".", 2)[0]
}

// parseListing recognizes only the reviewed cmsh JSON listing shape: after
// trimming surrounding whitespace, the entire text must decode as a JSON
// array of objects (a non-JSON prefix or suffix, such as an event line or an
// "ERROR:" message, fails the decode outright since json.Unmarshal requires
// the whole input to be one value). Each object must carry a non-empty
// string value for a key equal (case-insensitively) to "type" and a key
// whose lowercase form starts with "hostname" (the manual's documented
// column title is "hostname (key)"). Unknown extra keys are ignored.
// headListed reports whether any object's short hostname matches the plan
// host's short name; it never affects structured/devices.
//
// rows carries the parsed (type, hostname, category, status) rows in listing
// order. A "category" key is optional in the same way as "status": the access
// test never asks for the column, and a head node carries no category.
// The caller decides whether it is authorized to keep them: only the
// inventory discovery operation retains rows, and only after they pass the
// domain bounds. A "status" key is optional; its absence is not an error,
// since the pass/fail contract of the listing never depended on it.
func parseListing(stdout string, expectedHost string) (rows []domain.CredentialAccessDevice, devices int, headListed bool, structured bool) {
	trimmed := strings.TrimSpace(stdout)
	if trimmed == "" {
		return nil, 0, false, false
	}
	var items []map[string]any
	if err := json.Unmarshal([]byte(trimmed), &items); err != nil {
		return nil, 0, false, false
	}
	expectedShort := shortName(expectedHost)
	rows = make([]domain.CredentialAccessDevice, 0, len(items))
	for _, item := range items {
		var typeVal, hostVal, statusVal, categoryVal string
		for key, value := range item {
			lower := strings.ToLower(key)
			switch {
			case lower == "type":
				s, isStr := value.(string)
				if !isStr || s == "" {
					return nil, 0, false, false
				}
				typeVal = s
			case strings.HasPrefix(lower, "hostname"):
				s, isStr := value.(string)
				if !isStr || s == "" {
					return nil, 0, false, false
				}
				hostVal = s
			case strings.HasPrefix(lower, "status"):
				if s, isStr := value.(string); isStr {
					statusVal = s
				}
			case strings.HasPrefix(lower, "category"):
				// Optional, and legitimately empty: a head node carries no
				// category at all. An absent or empty category is a fact the
				// preview classifies on, never a parse failure.
				if s, isStr := value.(string); isStr {
					categoryVal = s
				}
			}
		}
		if typeVal == "" || hostVal == "" {
			return nil, 0, false, false
		}
		rows = append(rows, domain.CredentialAccessDevice{Type: typeVal, Hostname: hostVal, Category: categoryVal, Status: statusVal})
		devices++
		if strings.EqualFold(shortName(hostVal), expectedShort) {
			headListed = true
		}
	}
	return rows, devices, headListed, true
}

// Fixed, content-free reasons sanitizeDevices may refuse a row for. These are
// the only text an operator ever sees about *why* a listing was refused; the
// raw field values themselves are never included.
const (
	sanitizeRuleFieldTooLong     = "field_too_long"
	sanitizeRuleEmptyTypeOrHost  = "empty_type_or_hostname"
	sanitizeRuleDuplicate        = "duplicate_type_and_hostname"
	sanitizeRuleUnsanitizedField = "unsanitized_field"
)

// deviceSanitizeRefusal is the content-free record of why sanitizeDevices
// refused a listing: which fixed rule tripped, the 0-based ordinal of the
// offending row, and the byte lengths (never the text) of that row's raw
// type, hostname and status fields.
type deviceSanitizeRefusal struct {
	Rule       string
	RowOrdinal int
	TypeLen    int
	HostLen    int
	StatusLen  int
}

func (r deviceSanitizeRefusal) detail() string {
	return fmt.Sprintf("a device row did not match the reviewed bounds (row %d, rule %s, lengths %d/%d/%d)", r.RowOrdinal, r.Rule, r.TypeLen, r.HostLen, r.StatusLen)
}

func (r deviceSanitizeRefusal) summary() string {
	return fmt.Sprintf("The listing contained a device row outside the reviewed bounds (row %d, rule %s, lengths %d/%d/%d); no inventory was retained.", r.RowOrdinal, r.Rule, r.TypeLen, r.HostLen, r.StatusLen)
}

// sanitizeDevices bounds every retained field through the same sanitizer the
// server re-applies. A row that does not survive sanitization (an over-long
// type or hostname, an empty type or hostname, a duplicate (type, hostname)
// pair, or a field that does not come out of the sanitizer stable) makes the
// whole listing untrusted rather than being silently dropped or truncated.
//
// The status and category columns are descriptive rather than identity: an
// over-long raw value is truncated to CredentialAccessDeviceMaxField like
// every other sanitized field, never refused. Type and hostname keep the
// strict refuse-on-over-long rule, since a shortened hostname would be a
// different host.
//
// The refusal record still reports the type/hostname/status lengths only. The
// two rules that can trip on a length are both identity rules, so adding a
// fourth number would change a fixed operator text without ever explaining a
// refusal the existing three do not already explain.
func sanitizeDevices(rows []domain.CredentialAccessDevice) ([]domain.CredentialAccessDevice, *deviceSanitizeRefusal) {
	sanitized := make([]domain.CredentialAccessDevice, 0, len(rows))
	seen := make(map[string]struct{}, len(rows))
	for i, row := range rows {
		refusal := func(rule string) *deviceSanitizeRefusal {
			return &deviceSanitizeRefusal{Rule: rule, RowOrdinal: i, TypeLen: len(row.Type), HostLen: len(row.Hostname), StatusLen: len(row.Status)}
		}
		if len(row.Type) > domain.CredentialAccessDeviceMaxField || len(row.Hostname) > domain.CredentialAccessDeviceMaxField {
			return nil, refusal(sanitizeRuleFieldTooLong)
		}
		candidate := domain.CredentialAccessDevice{
			Type:     domain.SanitizeCredentialAccessText(row.Type, domain.CredentialAccessDeviceMaxField),
			Hostname: domain.SanitizeCredentialAccessText(row.Hostname, domain.CredentialAccessDeviceMaxField),
			Category: domain.SanitizeCredentialAccessText(row.Category, domain.CredentialAccessDeviceMaxField),
			Status:   domain.SanitizeCredentialAccessText(row.Status, domain.CredentialAccessDeviceMaxField),
		}
		if candidate.Type == "" || candidate.Hostname == "" {
			return nil, refusal(sanitizeRuleEmptyTypeOrHost)
		}
		for _, field := range []string{candidate.Type, candidate.Hostname, candidate.Category, candidate.Status} {
			if len(field) > domain.CredentialAccessDeviceMaxField || field != domain.SanitizeCredentialAccessText(field, domain.CredentialAccessDeviceMaxField) {
				return nil, refusal(sanitizeRuleUnsanitizedField)
			}
		}
		key := candidate.Type + "\x00" + candidate.Hostname
		if _, duplicate := seen[key]; duplicate {
			return nil, refusal(sanitizeRuleDuplicate)
		}
		seen[key] = struct{}{}
		sanitized = append(sanitized, candidate)
	}
	// Defensive backstop: the per-row checks above mirror
	// domain.ValidateCredentialAccessDevices exactly, so this should be
	// unreachable. Kept in case that invariant ever drifts.
	if domain.ValidateCredentialAccessDevices(sanitized) != nil {
		return nil, &deviceSanitizeRefusal{Rule: sanitizeRuleUnsanitizedField, RowOrdinal: len(sanitized) - 1}
	}
	return sanitized, nil
}

func shortName(value string) string {
	return strings.SplitN(strings.ToLower(strings.TrimSpace(value)), ".", 2)[0]
}

func redact(output []byte, secret []byte) string {
	if len(secret) > 0 {
		output = bytes.ReplaceAll(output, secret, []byte(redactedMarker))
	}
	return string(output)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, spec CommandSpec) CommandOutcome {
	outcome := CommandOutcome{ExitCode: -1}
	if spec.Timeout <= 0 || spec.MaxOutputBytes <= 0 {
		outcome.Err = errors.New("command limits are required")
		return outcome
	}
	runCtx, cancel := context.WithTimeout(ctx, spec.Timeout)
	defer cancel()
	command := exec.CommandContext(runCtx, spec.Path, spec.Args...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	command.Dir = "/"
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process != nil {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	command.WaitDelay = 2 * time.Second
	stdout := &boundedBuffer{limit: spec.MaxOutputBytes}
	stderr := &boundedBuffer{limit: spec.MaxOutputBytes}
	command.Stdout, command.Stderr = stdout, stderr
	var stdin, stdinWriter *os.File
	var stdinDone chan struct{}
	if len(spec.Stdin) > 0 {
		reader, writer, err := os.Pipe()
		if err != nil {
			outcome.Err = err
			return outcome
		}
		command.Stdin = reader
		stdin = reader
		stdinWriter = writer
		stdinDone = make(chan struct{})
		// The writer goroutine cannot leak: once we close our copy of the
		// read end below (right after Start), the only remaining reader is
		// the child's own fd. If the child never reads and exits without
		// consuming stdin, its fd closes too, the pipe becomes fully
		// closed for reads, and this Write returns EPIPE, ending the
		// goroutine. If the child (or a descendant that inherited the read
		// end) is merely slow, the explicit writer.Close() below, issued
		// after Wait returns, forces any still-blocked Write to unblock;
		// os.File Close is safe to call concurrently with an in-flight
		// Read/Write from another goroutine. Run always waits, with a bound,
		// for this goroutine to finish before returning.
		go func() {
			defer close(stdinDone)
			_, _ = writer.Write(spec.Stdin)
			_ = writer.Close()
		}()
	}
	if err := command.Start(); err != nil {
		if stdin != nil {
			_ = stdin.Close()
		}
		if stdinWriter != nil {
			_ = stdinWriter.Close()
		}
		outcome.Err = err
		return outcome
	}
	if stdin != nil {
		_ = stdin.Close()
	}
	outcome.Started = true
	err := command.Wait()
	outcome.Stdout, outcome.Stderr = stdout.Bytes(), stderr.Bytes()
	outcome.Truncated = stdout.truncated || stderr.truncated
	if command.ProcessState != nil {
		outcome.ExitCode = command.ProcessState.ExitCode()
	}
	if runCtx.Err() != nil && ctx.Err() == nil {
		outcome.TimedOut = true
	}
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			// Includes exec.ErrWaitDelay: the child exited but I/O (or a
			// descendant holding a copy of stdout/stderr) did not finish
			// within WaitDelay. Never trust a result from a run that did
			// not terminate cleanly.
			outcome.Err = err
		}
	}

	// Unconditionally reap the whole process group after Wait returns, on
	// every path (success, error, timeout). Setpgid means SIGKILL to the
	// negative pid reaches every descendant still in this session's process
	// group, including one holding stdout/stderr open that caused
	// ErrWaitDelay above. A descendant that escaped the group (for example
	// by calling setsid) cannot be reached this way; in that case Wait's
	// ErrWaitDelay (set above) still fails the check.
	if command.Process != nil {
		pid := command.Process.Pid
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		reapDeadline := time.Now().Add(command.WaitDelay)
		for {
			if killErr := syscall.Kill(-pid, 0); errors.Is(killErr, syscall.ESRCH) {
				break
			}
			if time.Now().After(reapDeadline) {
				outcome.Err = errDescendantsAlive
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Explicitly close our copy of the stdin writer (a no-op if the
	// goroutine already closed it) so any Write it still has blocked on
	// unblocks, then wait, bounded, for the goroutine to actually exit.
	if stdinWriter != nil {
		_ = stdinWriter.Close()
	}
	if stdinDone != nil {
		select {
		case <-stdinDone:
		case <-time.After(command.WaitDelay):
			if outcome.Err == nil {
				outcome.Err = errDescendantsAlive
			}
		}
	}

	return outcome
}

type boundedBuffer struct {
	buffer    bytes.Buffer
	limit     int64
	truncated bool
}

func (b *boundedBuffer) Write(payload []byte) (int, error) {
	remaining := b.limit - int64(b.buffer.Len())
	if remaining > 0 {
		if int64(len(payload)) > remaining {
			b.buffer.Write(payload[:remaining])
			b.truncated = true
		} else {
			b.buffer.Write(payload)
		}
	} else if len(payload) > 0 {
		b.truncated = true
	}
	return len(payload), nil
}

func (b *boundedBuffer) Bytes() []byte { return append([]byte(nil), b.buffer.Bytes()...) }
