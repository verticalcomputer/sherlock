package domain

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// CredentialAccessTestOperation is the reviewed operation identifier and
// collector capability name for the head-local BCM access test. It is not a
// collection operation: it has its own durable table, endpoint family and
// result shape, and it never carries a secret.
const CredentialAccessTestOperation = "bcm.access_test.v1"

// CredentialInventoryDiscoveryOperation is the second reviewed operation of
// the same family. It runs the identical fixed, live-qualified cmsh listing
// as the access test; the only difference is that the sanitized device rows
// are retained so an operator can later build an expected-inventory preview.
// It is not a generic executor: no argument, command or field selection is
// ever derived from the plan, the operator or a model.
const CredentialInventoryDiscoveryOperation = "bcm.inventory_discovery.v1"

// CredentialAccessOperations is the closed set of operations the credential
// access-test family will schedule, claim, deliver for and complete.
func CredentialAccessOperations() []string {
	return []string{CredentialAccessTestOperation, CredentialInventoryDiscoveryOperation}
}

// IsCredentialAccessOperation reports membership of that closed set. Every
// boundary that accepts an operation name uses this and nothing else.
func IsCredentialAccessOperation(op string) bool {
	return op == CredentialAccessTestOperation || op == CredentialInventoryDiscoveryOperation
}

// CredentialAccessTestSchemaVersion versions the plan and result documents.
const CredentialAccessTestSchemaVersion = 1

const (
	CredentialAccessTestPurpose         = "BCM_READ_ONLY"
	CredentialAccessPasswordlessPurpose = "BCM_READ_ONLY_PASSWORDLESS"
	CredentialAccessTestMaxSummary      = 512
	CredentialAccessTestMaxVersion      = 64
	CredentialAccessTestMaxChecks       = 8
	CredentialAccessTestMaxAttempts     = 2
	CredentialAccessTestMinTimeout      = 5 * time.Second
	CredentialAccessTestMaxTimeout      = 120 * time.Second
	CredentialAccessTestDefaultTimeout  = 30 * time.Second
	CredentialAccessTestMaxOutputBytes  = 64 << 10
	CredentialAccessTestMaxDeadline     = time.Hour

	// CredentialAccessTestMaxDevices bounds how many device rows the
	// inventory discovery operation may retain. A listing larger than this is
	// reported as unexpected output rather than truncated: a partial
	// inventory must never be persisted as if it were complete.
	CredentialAccessTestMaxDevices = 512
	// CredentialAccessDeviceMaxField bounds each retained device field.
	CredentialAccessDeviceMaxField = 128
)

// CredentialAccessTestStatus is the durable state of one requested test.
type CredentialAccessTestStatus string

const (
	CredentialAccessTestRequested CredentialAccessTestStatus = "REQUESTED"
	CredentialAccessTestClaimed   CredentialAccessTestStatus = "CLAIMED"
	CredentialAccessTestRunning   CredentialAccessTestStatus = "RUNNING"
	CredentialAccessTestSucceeded CredentialAccessTestStatus = "SUCCEEDED"
	CredentialAccessTestFailed    CredentialAccessTestStatus = "FAILED"
	CredentialAccessTestExpired   CredentialAccessTestStatus = "EXPIRED"
	CredentialAccessTestCancelled CredentialAccessTestStatus = "CANCELLED"
)

func (s CredentialAccessTestStatus) Terminal() bool {
	switch s {
	case CredentialAccessTestSucceeded, CredentialAccessTestFailed, CredentialAccessTestExpired, CredentialAccessTestCancelled:
		return true
	}
	return false
}

func (s CredentialAccessTestStatus) Validate() error {
	switch s {
	case CredentialAccessTestRequested, CredentialAccessTestClaimed, CredentialAccessTestRunning,
		CredentialAccessTestSucceeded, CredentialAccessTestFailed, CredentialAccessTestExpired, CredentialAccessTestCancelled:
		return nil
	}
	return fmt.Errorf("unknown credential access test status %q", s)
}

// CredentialAccessOutcome is the closed set of terminal codes a head may
// report. Free-form failure text is never accepted from the head.
type CredentialAccessOutcome string

const (
	CredentialAccessVerified              CredentialAccessOutcome = "BCM_ACCESS_VERIFIED"
	CredentialAccessPasswordlessVerified  CredentialAccessOutcome = "BCM_PASSWORDLESS_ACCESS_VERIFIED"
	CredentialAccessSudoAuthFailed        CredentialAccessOutcome = "SUDO_AUTH_FAILED"
	CredentialAccessSudoPasswordless      CredentialAccessOutcome = "SUDO_PASSWORDLESS"
	CredentialAccessSudoPromptUnexpected  CredentialAccessOutcome = "SUDO_PROMPT_UNEXPECTED"
	CredentialAccessSudoPolicyUnsupported CredentialAccessOutcome = "SUDO_POLICY_UNSUPPORTED"
	CredentialAccessCommandUnavailable    CredentialAccessOutcome = "BCM_COMMAND_UNAVAILABLE"
	CredentialAccessVersionUnsupported    CredentialAccessOutcome = "BCM_VERSION_UNSUPPORTED"
	CredentialAccessOutputUnexpected      CredentialAccessOutcome = "BCM_OUTPUT_UNEXPECTED"
	CredentialAccessLoginMismatch         CredentialAccessOutcome = "LOGIN_IDENTITY_MISMATCH"
	CredentialAccessHostMismatch          CredentialAccessOutcome = "HOST_MISMATCH"
	CredentialAccessCredentialUnavailable CredentialAccessOutcome = "CREDENTIAL_UNAVAILABLE"
	CredentialAccessExecutionUnsupported  CredentialAccessOutcome = "EXECUTION_UNSUPPORTED"
	CredentialAccessTimedOut              CredentialAccessOutcome = "TIMED_OUT"
	CredentialAccessCancelled             CredentialAccessOutcome = "CANCELLED"
	CredentialAccessInternal              CredentialAccessOutcome = "INTERNAL"
)

func (o CredentialAccessOutcome) Validate() error {
	switch o {
	case CredentialAccessVerified, CredentialAccessPasswordlessVerified, CredentialAccessSudoAuthFailed, CredentialAccessSudoPasswordless, CredentialAccessSudoPromptUnexpected,
		CredentialAccessSudoPolicyUnsupported, CredentialAccessCommandUnavailable, CredentialAccessVersionUnsupported,
		CredentialAccessOutputUnexpected, CredentialAccessLoginMismatch, CredentialAccessHostMismatch,
		CredentialAccessCredentialUnavailable, CredentialAccessExecutionUnsupported, CredentialAccessTimedOut,
		CredentialAccessCancelled, CredentialAccessInternal:
		return nil
	}
	return fmt.Errorf("unknown credential access outcome %q", o)
}

// Success reports whether the outcome proves working read-only BCM access.
func (o CredentialAccessOutcome) Success() bool {
	return o == CredentialAccessVerified || o == CredentialAccessPasswordlessVerified
}

// CredentialAccessTestLimits bounds head execution. They are reviewed
// constants chosen by the server, not collector or operator input.
type CredentialAccessTestLimits struct {
	TimeoutSeconds int   `json:"timeout_seconds"`
	MaxOutputBytes int64 `json:"max_output_bytes"`
}

// CredentialAccessTestPlan is the secret-free description of one test. It is
// what the collector claims, what the plan digest covers, and what the head
// compares against its own identity before executing anything. Credential
// identity is named by id and exact version; the password is never part of
// the plan, the durable row, the journal, the result or any log.
type CredentialAccessTestPlan struct {
	SchemaVersion     int                        `json:"schema_version"`
	TestID            string                     `json:"test_id"`
	ClusterID         ClusterID                  `json:"cluster_id"`
	Operation         string                     `json:"operation"`
	Host              string                     `json:"host"`
	Purpose           string                     `json:"purpose"`
	Username          string                     `json:"username"`
	CredentialID      string                     `json:"credential_id"`
	CredentialVersion int64                      `json:"credential_version"`
	RequestedAt       time.Time                  `json:"requested_at"`
	Deadline          time.Time                  `json:"deadline"`
	Limits            CredentialAccessTestLimits `json:"limits"`
}

func ValidateCredentialAccessTestPlan(plan CredentialAccessTestPlan) error {
	if plan.SchemaVersion != CredentialAccessTestSchemaVersion || !IsCredentialAccessOperation(plan.Operation) {
		return fmt.Errorf("credential access test plan version or operation is unsupported")
	}
	if !ValidCredentialAccessTestID(plan.TestID) || !validControlID(string(plan.ClusterID)) {
		return fmt.Errorf("credential access test identifiers are invalid")
	}
	if !validCredentialAccessHost(plan.Host) || (plan.Purpose != CredentialAccessTestPurpose && plan.Purpose != CredentialAccessPasswordlessPurpose) || !validCredentialAccessUsername(plan.Username) {
		return fmt.Errorf("credential access test target binding is invalid")
	}
	if !validCredentialAccessCredentialID(plan.CredentialID) || plan.CredentialVersion < 1 {
		return fmt.Errorf("credential access test credential reference is invalid")
	}
	if plan.RequestedAt.IsZero() || !plan.Deadline.After(plan.RequestedAt) || plan.Deadline.Sub(plan.RequestedAt) > CredentialAccessTestMaxDeadline {
		return fmt.Errorf("credential access test deadline is invalid")
	}
	timeout := time.Duration(plan.Limits.TimeoutSeconds) * time.Second
	if timeout < CredentialAccessTestMinTimeout || timeout > CredentialAccessTestMaxTimeout {
		return fmt.Errorf("credential access test timeout is outside its bounds")
	}
	if plan.Limits.MaxOutputBytes < 1024 || plan.Limits.MaxOutputBytes > CredentialAccessTestMaxOutputBytes {
		return fmt.Errorf("credential access test output bound is outside its limits")
	}
	return nil
}

// CredentialAccessTestPlanDigest is the canonical binding used by delivery
// and result submission. It hashes the canonical JSON encoding of the plan
// with UTC timestamps, so a plan copied through any transport digests the same.
func CredentialAccessTestPlanDigest(plan CredentialAccessTestPlan) (SHA256, error) {
	if err := ValidateCredentialAccessTestPlan(plan); err != nil {
		return SHA256{}, err
	}
	plan.RequestedAt = plan.RequestedAt.UTC()
	plan.Deadline = plan.Deadline.UTC()
	encoded, err := json.Marshal(plan)
	if err != nil {
		return SHA256{}, err
	}
	return sha256.Sum256(encoded), nil
}

// CredentialAccessCheck is one step of the fixed head contract. Detail is a
// bounded, sanitized phrase; never raw command output.
type CredentialAccessCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

const (
	CredentialAccessCheckPassed  = "PASSED"
	CredentialAccessCheckFailed  = "FAILED"
	CredentialAccessCheckSkipped = "SKIPPED"
)

// CredentialAccessDevice is one sanitized row of the fixed cmsh device
// listing. It carries only the reviewed columns and never raw command output:
// every field is sanitized and bounded by the head before it leaves and
// re-checked by the server before it is stored.
//
// Category is the BCM device category and is populated by the inventory
// discovery operation alone, whose fixed command asks for the column. It is
// legitimately empty — a head node carries no category — and it is BCM
// configuration, not a secret and not a telemetry fact.
type CredentialAccessDevice struct {
	Type     string `json:"type"`
	Hostname string `json:"hostname"`
	Category string `json:"category,omitempty"`
	Status   string `json:"status"`
}

// ValidateCredentialAccessDevices bounds and sanitizes a retained listing.
// Type and hostname must be present; status and category may be empty because
// both columns are optional. Duplicate (type, hostname) pairs are refused so
// the durable unique constraint can never be the first thing that notices:
// category is descriptive and is deliberately not part of that identity.
func ValidateCredentialAccessDevices(devices []CredentialAccessDevice) error {
	if len(devices) > CredentialAccessTestMaxDevices {
		return fmt.Errorf("credential access device listing exceeds its retained bound")
	}
	seen := make(map[string]struct{}, len(devices))
	for _, device := range devices {
		if device.Type == "" || device.Hostname == "" {
			return fmt.Errorf("credential access device row is missing its type or hostname")
		}
		for _, field := range []string{device.Type, device.Hostname, device.Category, device.Status} {
			if len(field) > CredentialAccessDeviceMaxField || field != SanitizeCredentialAccessText(field, CredentialAccessDeviceMaxField) {
				return fmt.Errorf("credential access device field is unbounded or unsanitized")
			}
		}
		key := device.Type + "\x00" + device.Hostname
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("credential access device listing repeats a (type, hostname) pair")
		}
		seen[key] = struct{}{}
	}
	return nil
}

// CredentialAccessTestResult is the head's secret-free report. Summary and
// check details are sanitized and bounded before they are accepted. Devices
// is populated only by the inventory discovery operation on a verified
// outcome; every other operation and outcome must leave it empty.
type CredentialAccessTestResult struct {
	SchemaVersion int                      `json:"schema_version"`
	TestID        string                   `json:"test_id"`
	Attempt       int                      `json:"attempt"`
	PlanDigest    string                   `json:"plan_digest"`
	Outcome       CredentialAccessOutcome  `json:"outcome"`
	Summary       string                   `json:"summary"`
	BCMVersion    string                   `json:"bcm_version,omitempty"`
	DevicesListed int                      `json:"devices_listed"`
	StartedAt     time.Time                `json:"started_at"`
	CompletedAt   time.Time                `json:"completed_at"`
	Checks        []CredentialAccessCheck  `json:"checks"`
	Devices       []CredentialAccessDevice `json:"devices,omitempty"`
}

func ValidateCredentialAccessTestResult(result CredentialAccessTestResult) error {
	if result.SchemaVersion != CredentialAccessTestSchemaVersion || !ValidCredentialAccessTestID(result.TestID) || result.Attempt < 1 || result.Attempt > CredentialAccessTestMaxAttempts {
		return fmt.Errorf("credential access test result envelope is invalid")
	}
	if len(result.PlanDigest) != 64 || !isLowerHex(result.PlanDigest) {
		return fmt.Errorf("credential access test result plan digest is invalid")
	}
	if err := result.Outcome.Validate(); err != nil {
		return err
	}
	if result.Summary == "" || len(result.Summary) > CredentialAccessTestMaxSummary || result.Summary != SanitizeCredentialAccessText(result.Summary, CredentialAccessTestMaxSummary) {
		return fmt.Errorf("credential access test summary is missing, unbounded or unsanitized")
	}
	if len(result.BCMVersion) > CredentialAccessTestMaxVersion || result.BCMVersion != SanitizeCredentialAccessText(result.BCMVersion, CredentialAccessTestMaxVersion) {
		return fmt.Errorf("credential access test version text is invalid")
	}
	if result.DevicesListed < 0 || result.DevicesListed > 1_000_000 {
		return fmt.Errorf("credential access test device count is out of range")
	}
	if result.StartedAt.IsZero() || result.CompletedAt.Before(result.StartedAt) {
		return fmt.Errorf("credential access test timestamps are invalid")
	}
	if len(result.Checks) > CredentialAccessTestMaxChecks {
		return fmt.Errorf("credential access test reports too many checks")
	}
	seen := make(map[string]struct{}, len(result.Checks))
	for _, check := range result.Checks {
		if !validControlID(check.Name) {
			return fmt.Errorf("credential access check name is invalid")
		}
		if _, duplicate := seen[check.Name]; duplicate {
			return fmt.Errorf("credential access check names must be unique")
		}
		seen[check.Name] = struct{}{}
		switch check.Status {
		case CredentialAccessCheckPassed, CredentialAccessCheckFailed, CredentialAccessCheckSkipped:
		default:
			return fmt.Errorf("credential access check status is invalid")
		}
		if len(check.Detail) > CredentialAccessTestMaxSummary || check.Detail != SanitizeCredentialAccessText(check.Detail, CredentialAccessTestMaxSummary) {
			return fmt.Errorf("credential access check detail is invalid")
		}
	}
	if result.Outcome.Success() && result.DevicesListed < 1 {
		return fmt.Errorf("verified access requires at least one listed device")
	}
	if err := ValidateCredentialAccessDevices(result.Devices); err != nil {
		return err
	}
	// A non-verified outcome never retains a listing: a partial or
	// unrecognized listing must not be persisted as if it were an inventory.
	if !result.Outcome.Success() && len(result.Devices) > 0 {
		return fmt.Errorf("a non-verified credential access result must not carry device rows")
	}
	return nil
}

// ValidateCredentialAccessTestResultForPlan binds a submitted result to the
// server's stored plan. The submitted document never carries authority.
func ValidateCredentialAccessTestResultForPlan(result CredentialAccessTestResult, plan CredentialAccessTestPlan, attempt int) error {
	if err := ValidateCredentialAccessTestResult(result); err != nil {
		return err
	}
	digest, err := CredentialAccessTestPlanDigest(plan)
	if err != nil {
		return err
	}
	if result.TestID != plan.TestID || result.Attempt != attempt || result.PlanDigest != digest.String() {
		return fmt.Errorf("credential access test result does not match its leased plan")
	}
	if (result.Outcome == CredentialAccessPasswordlessVerified && plan.Purpose != CredentialAccessPasswordlessPurpose) || (result.Outcome == CredentialAccessVerified && plan.Purpose != CredentialAccessTestPurpose) {
		return fmt.Errorf("credential access test outcome does not match its authorization mode")
	}
	// Which operation was authorized decides whether a listing may be
	// retained at all. The access test never retains one; the inventory
	// discovery retains exactly the rows it counted, and only when verified.
	switch plan.Operation {
	case CredentialAccessTestOperation:
		if len(result.Devices) > 0 {
			return fmt.Errorf("the access test operation does not retain device rows")
		}
	case CredentialInventoryDiscoveryOperation:
		if result.Outcome.Success() {
			if len(result.Devices) < 1 || len(result.Devices) != result.DevicesListed {
				return fmt.Errorf("a verified inventory discovery must retain exactly the device rows it counted")
			}
		} else if len(result.Devices) > 0 {
			return fmt.Errorf("an unverified inventory discovery must not retain device rows")
		}
	default:
		return fmt.Errorf("credential access test plan operation is unsupported")
	}
	return nil
}

// SanitizeCredentialAccessText keeps printable characters only, collapses
// whitespace and bounds the length. It is applied by producers before a
// result leaves the head and re-checked by the server.
func SanitizeCredentialAccessText(value string, limit int) string {
	var builder strings.Builder
	lastSpace := false
	for _, r := range value {
		if r == '\n' || r == '\t' || r == '\r' || unicode.IsSpace(r) {
			if !lastSpace && builder.Len() > 0 {
				builder.WriteByte(' ')
				lastSpace = true
			}
			continue
		}
		if r == unicode.ReplacementChar || !unicode.IsPrint(r) {
			continue
		}
		builder.WriteRune(r)
		lastSpace = false
	}
	sanitized := strings.TrimSpace(builder.String())
	if len(sanitized) > limit {
		cut := limit
		for cut > 0 && cut < len(sanitized) && (sanitized[cut]&0xC0) == 0x80 {
			cut--
		}
		sanitized = strings.TrimSpace(sanitized[:cut])
	}
	return sanitized
}

func ValidCredentialAccessTestID(value string) bool {
	return strings.HasPrefix(value, "ctest_") && validControlID(value)
}

func validCredentialAccessCredentialID(value string) bool {
	return strings.HasPrefix(value, "cred_") && len(value) <= 128 && validControlID(value)
}

func validCredentialAccessHost(value string) bool {
	if len(value) < 1 || len(value) > 256 || value != strings.TrimSpace(value) {
		return false
	}
	for _, r := range value {
		if r == 0 || unicode.IsSpace(r) || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func validCredentialAccessUsername(value string) bool {
	return validCredentialAccessHost(value)
}

func isLowerHex(value string) bool {
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
