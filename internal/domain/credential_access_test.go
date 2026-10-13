package domain

import (
	"strings"
	"testing"
	"time"
)

func validAccessPlan() CredentialAccessTestPlan {
	now := time.Date(2026, 9, 21, 9, 0, 0, 0, time.UTC)
	return CredentialAccessTestPlan{SchemaVersion: 1, TestID: "ctest_abc", ClusterID: "pilot-cluster", Operation: CredentialAccessTestOperation, Host: "fixture1-zone1-headnode", Purpose: CredentialAccessTestPurpose, Username: "fixture_user_1", CredentialID: "cred_abc", CredentialVersion: 2, RequestedAt: now, Deadline: now.Add(15 * time.Minute), Limits: CredentialAccessTestLimits{TimeoutSeconds: 30, MaxOutputBytes: 65536}}
}

func TestCredentialAccessOutcomeMustMatchAuthorizationMode(t *testing.T) {
	plan := validAccessPlan()
	plan.Purpose = CredentialAccessPasswordlessPurpose
	digest, err := CredentialAccessTestPlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	result := CredentialAccessTestResult{SchemaVersion: 1, TestID: plan.TestID, Attempt: 1, PlanDigest: digest.String(), Outcome: CredentialAccessPasswordlessVerified, Summary: "passwordless listing succeeded", DevicesListed: 2, StartedAt: plan.RequestedAt, CompletedAt: plan.RequestedAt.Add(time.Second)}
	if err := ValidateCredentialAccessTestResultForPlan(result, plan, 1); err != nil {
		t.Fatal(err)
	}
	result.Outcome = CredentialAccessVerified
	if err := ValidateCredentialAccessTestResultForPlan(result, plan, 1); err == nil {
		t.Fatal("password credential result accepted for passwordless authorization")
	}
}

func TestCredentialAccessTestPlanDigestIsCanonicalAndBindsEveryField(t *testing.T) {
	plan := validAccessPlan()
	digest, err := CredentialAccessTestPlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	shifted := plan
	shifted.RequestedAt = plan.RequestedAt.In(time.FixedZone("IST", 5*3600+1800))
	if again, _ := CredentialAccessTestPlanDigest(shifted); again != digest {
		t.Fatal("digest must not depend on the timestamp zone")
	}
	for name, mutate := range map[string]func(*CredentialAccessTestPlan){
		"host":     func(p *CredentialAccessTestPlan) { p.Host = "other-head" },
		"username": func(p *CredentialAccessTestPlan) { p.Username = "root" },
		"version":  func(p *CredentialAccessTestPlan) { p.CredentialVersion = 3 },
		"id":       func(p *CredentialAccessTestPlan) { p.CredentialID = "cred_other" },
		"deadline": func(p *CredentialAccessTestPlan) { p.Deadline = p.Deadline.Add(time.Second) },
		"limits":   func(p *CredentialAccessTestPlan) { p.Limits.TimeoutSeconds = 31 },
	} {
		changed := plan
		mutate(&changed)
		if other, err := CredentialAccessTestPlanDigest(changed); err != nil || other == digest {
			t.Fatalf("%s change did not alter the digest (%v)", name, err)
		}
	}
	for name, mutate := range map[string]func(*CredentialAccessTestPlan){
		"operation":     func(p *CredentialAccessTestPlan) { p.Operation = "bcm.shell.v1" },
		"purpose":       func(p *CredentialAccessTestPlan) { p.Purpose = "BCM_ADMIN" },
		"timeout":       func(p *CredentialAccessTestPlan) { p.Limits.TimeoutSeconds = 600 },
		"long deadline": func(p *CredentialAccessTestPlan) { p.Deadline = p.RequestedAt.Add(2 * time.Hour) },
		"bad test id":   func(p *CredentialAccessTestPlan) { p.TestID = "work-1" },
		"host space":    func(p *CredentialAccessTestPlan) { p.Host = "head one" },
	} {
		changed := plan
		mutate(&changed)
		if err := ValidateCredentialAccessTestPlan(changed); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestCredentialAccessTestResultRequiresSanitizedBoundedClosedOutcomes(t *testing.T) {
	plan := validAccessPlan()
	digest, _ := CredentialAccessTestPlanDigest(plan)
	result := CredentialAccessTestResult{SchemaVersion: 1, TestID: plan.TestID, Attempt: 1, PlanDigest: digest.String(), Outcome: CredentialAccessVerified, Summary: "ok", DevicesListed: 2, StartedAt: plan.RequestedAt, CompletedAt: plan.RequestedAt.Add(time.Second)}
	if err := ValidateCredentialAccessTestResultForPlan(result, plan, 1); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCredentialAccessTestResultForPlan(result, plan, 2); err == nil {
		t.Fatal("attempt mismatch accepted")
	}
	bad := result
	bad.Outcome = "SHELL_OK"
	if err := ValidateCredentialAccessTestResult(bad); err == nil {
		t.Fatal("unknown outcome accepted")
	}
	bad = result
	bad.Summary = "password: secret\x00\n"
	if err := ValidateCredentialAccessTestResult(bad); err == nil {
		t.Fatal("unsanitized summary accepted")
	}
	bad = result
	bad.Summary = strings.Repeat("x", CredentialAccessTestMaxSummary+1)
	if err := ValidateCredentialAccessTestResult(bad); err == nil {
		t.Fatal("unbounded summary accepted")
	}
	bad = result
	bad.DevicesListed = 0
	if err := ValidateCredentialAccessTestResult(bad); err == nil {
		t.Fatal("verified result without devices accepted")
	}
	bad = result
	bad.PlanDigest = strings.Repeat("0", 64)
	if err := ValidateCredentialAccessTestResultForPlan(bad, plan, 1); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	if got := SanitizeCredentialAccessText("  line one\n\tline\x07 two   ", 9); got != "line one" {
		t.Fatalf("sanitize produced %q", got)
	}
	if got := SanitizeCredentialAccessText("héllo wörld", 6); got != "héllo" {
		t.Fatalf("sanitize cut a rune: %q", got)
	}
}

func TestCredentialAccessSudoPasswordlessIsValidButNeverSuccess(t *testing.T) {
	if err := CredentialAccessSudoPasswordless.Validate(); err != nil {
		t.Fatalf("SUDO_PASSWORDLESS should be a recognized outcome: %v", err)
	}
	if CredentialAccessSudoPasswordless.Success() {
		t.Fatal("SUDO_PASSWORDLESS must never report success; only BCM_ACCESS_VERIFIED proves the credential")
	}
	plan := validAccessPlan()
	digest, _ := CredentialAccessTestPlanDigest(plan)
	result := CredentialAccessTestResult{SchemaVersion: 1, TestID: plan.TestID, Attempt: 1, PlanDigest: digest.String(), Outcome: CredentialAccessSudoPasswordless, Summary: "sudo did not request a password", DevicesListed: 0, StartedAt: plan.RequestedAt, CompletedAt: plan.RequestedAt.Add(time.Second)}
	if err := ValidateCredentialAccessTestResultForPlan(result, plan, 1); err != nil {
		t.Fatalf("passwordless result with zero devices should validate: %v", err)
	}
}

// The plan digest is what binds delivery and result submission to the exact
// authorized work, so two plans that differ only in operation must never
// digest the same: otherwise a lease for one could be spent on the other.
func TestCredentialAccessPlanDigestSeparatesOperations(t *testing.T) {
	accessPlan := validAccessPlan()
	inventoryPlan := accessPlan
	inventoryPlan.Operation = CredentialInventoryDiscoveryOperation
	accessDigest, err := CredentialAccessTestPlanDigest(accessPlan)
	if err != nil {
		t.Fatal(err)
	}
	inventoryDigest, err := CredentialAccessTestPlanDigest(inventoryPlan)
	if err != nil {
		t.Fatal(err)
	}
	if accessDigest == inventoryDigest {
		t.Fatal("plans differing only in operation digest the same")
	}
	unreviewed := accessPlan
	unreviewed.Operation = "bcm.anything_else.v1"
	if err := ValidateCredentialAccessTestPlan(unreviewed); err == nil {
		t.Fatal("an unreviewed operation was accepted")
	}
	if !IsCredentialAccessOperation(CredentialAccessTestOperation) || !IsCredentialAccessOperation(CredentialInventoryDiscoveryOperation) ||
		IsCredentialAccessOperation("") || IsCredentialAccessOperation("bcm.anything_else.v1") {
		t.Fatal("operation membership is wrong")
	}
	if operations := CredentialAccessOperations(); len(operations) != 2 {
		t.Fatalf("operations = %v", operations)
	}
}

func verifiedResult(plan CredentialAccessTestPlan, devices []CredentialAccessDevice, listed int) CredentialAccessTestResult {
	digest, _ := CredentialAccessTestPlanDigest(plan)
	now := time.Date(2026, 9, 21, 9, 5, 0, 0, time.UTC)
	return CredentialAccessTestResult{
		SchemaVersion: 1, TestID: plan.TestID, Attempt: 1, PlanDigest: digest.String(),
		Outcome: CredentialAccessVerified, Summary: "listed devices", BCMVersion: "10.0",
		DevicesListed: listed, StartedAt: now, CompletedAt: now, Devices: devices,
	}
}

func TestCredentialAccessResultRetainsDevicesOnlyForVerifiedInventoryDiscovery(t *testing.T) {
	accessPlan := validAccessPlan()
	inventoryPlan := accessPlan
	inventoryPlan.Operation = CredentialInventoryDiscoveryOperation
	rows := []CredentialAccessDevice{{Type: "HeadNode", Hostname: "fixture1-zone1-headnode", Status: "[ UP ]"}, {Type: "PhysicalNode", Hostname: "node001"}}

	if err := ValidateCredentialAccessTestResultForPlan(verifiedResult(inventoryPlan, rows, 2), inventoryPlan, 1); err != nil {
		t.Fatalf("well-formed inventory result rejected: %v", err)
	}
	if err := ValidateCredentialAccessTestResultForPlan(verifiedResult(accessPlan, nil, 2), accessPlan, 1); err != nil {
		t.Fatalf("well-formed access test result rejected: %v", err)
	}
	// An access test may never carry rows, whatever the head claims.
	if err := ValidateCredentialAccessTestResultForPlan(verifiedResult(accessPlan, rows, 2), accessPlan, 1); err == nil {
		t.Fatal("access test result with device rows accepted")
	}
	// A verified discovery must retain exactly what it counted.
	if err := ValidateCredentialAccessTestResultForPlan(verifiedResult(inventoryPlan, rows, 3), inventoryPlan, 1); err == nil {
		t.Fatal("inventory result with a mismatched count accepted")
	}
	if err := ValidateCredentialAccessTestResultForPlan(verifiedResult(inventoryPlan, nil, 0), inventoryPlan, 1); err == nil {
		t.Fatal("verified inventory result with no rows accepted")
	}
	// A partial listing is never persisted: a failed outcome carries no rows.
	failed := verifiedResult(inventoryPlan, rows, 2)
	failed.Outcome = CredentialAccessOutputUnexpected
	failed.DevicesListed = 0
	if err := ValidateCredentialAccessTestResult(failed); err == nil {
		t.Fatal("unverified result with device rows accepted")
	}
	if err := ValidateCredentialAccessTestResultForPlan(failed, inventoryPlan, 1); err == nil {
		t.Fatal("unverified inventory result with device rows accepted")
	}
}

func TestValidateCredentialAccessDevicesBounds(t *testing.T) {
	tooMany := make([]CredentialAccessDevice, 0, CredentialAccessTestMaxDevices+1)
	for i := 0; i <= CredentialAccessTestMaxDevices; i++ {
		tooMany = append(tooMany, CredentialAccessDevice{Type: "PhysicalNode", Hostname: "node" + strings.Repeat("0", i%3) + string(rune('a'+i%26)) + strings.Repeat("x", i/26)})
	}
	for name, devices := range map[string][]CredentialAccessDevice{
		"missing type":     {{Hostname: "node001"}},
		"missing hostname": {{Type: "PhysicalNode"}},
		"over-long field":  {{Type: "PhysicalNode", Hostname: strings.Repeat("n", CredentialAccessDeviceMaxField+1)}},
		"control chars":    {{Type: "PhysicalNode", Hostname: "node\x00001"}},
		"duplicate pair":   {{Type: "PhysicalNode", Hostname: "node001"}, {Type: "PhysicalNode", Hostname: "node001", Status: "DOWN"}},
		"over the bound":   tooMany,
	} {
		if err := ValidateCredentialAccessDevices(devices); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// The same hostname under a different type is a distinct row.
	if err := ValidateCredentialAccessDevices([]CredentialAccessDevice{{Type: "HeadNode", Hostname: "node001"}, {Type: "PhysicalNode", Hostname: "node001"}}); err != nil {
		t.Fatalf("distinct (type, hostname) pairs rejected: %v", err)
	}
}

// TestSanitizeCredentialAccessTextIsIdempotent proves Sanitize(Sanitize(x))
// == Sanitize(x) for a set of tricky inputs: an NBSP, tabs, an embedded ESC
// control character, trailing spaces, and multi-byte runes that land right
// at or across the truncation boundary. ValidateCredentialAccessDevices
// (and bcmaccess.sanitizeDevices) re-check a field against
// SanitizeCredentialAccessText(field, limit) after it has already been
// sanitized once; if the sanitizer were not idempotent, that re-check would
// spuriously fail even on output the sanitizer itself produced, surfacing as
// an unexplained "unsanitized_field" refusal on an otherwise clean listing.
func TestSanitizeCredentialAccessTextIsIdempotent(t *testing.T) {
	tricky := []string{
		"a b c",                            // NBSP
		"tab\ttab\ttab\ttab\ttab",          // tabs
		"esc\x1bhere\x1bthere",             // embedded ESC
		"trailing spaces at the end      ", // trailing spaces
		"日本語のテストです、境界に近い文字列です", // multi-byte runes spanning the limit
		"あああああああああああ",
		strings.Repeat("é", 20),
		"mixed   nbsp \t tab \x1b esc   trailing   ",
		strings.Repeat("字", 5) + "  " + strings.Repeat("字", 5),
		"  leading and trailing  ",
	}
	limits := []int{1, 2, 3, 5, 8, 9, 12, 16, 32, CredentialAccessDeviceMaxField}
	for _, in := range tricky {
		for _, limit := range limits {
			once := SanitizeCredentialAccessText(in, limit)
			twice := SanitizeCredentialAccessText(once, limit)
			if once != twice {
				t.Fatalf("SanitizeCredentialAccessText not idempotent for input %q at limit %d: once=%q twice=%q", in, limit, once, twice)
			}
			if len(once) > limit {
				t.Fatalf("SanitizeCredentialAccessText(%q, %d) = %q exceeds the limit (%d bytes)", in, limit, once, len(once))
			}
		}
	}
}
