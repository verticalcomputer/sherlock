package domain

import "testing"

func TestDiagnosticFailureCodesDoNotExposeUntrustedMessages(t *testing.T) {
	for _, code := range []string{"ssh password=secret", "DISPATCH_FAILED\nsecret", "PRIVATE_TOKEN"} {
		if SafeDiagnosticFailureCode(code) != "DIAGNOSTIC_FAILURE_UNCLASSIFIED" {
			t.Fatalf("unsafe code admitted: %q", code)
		}
	}
	if SafeDiagnosticFailureCode("TARGET_ROLE_UNAVAILABLE") != "TARGET_ROLE_UNAVAILABLE" || DiagnosticFailureReason("DISPATCH_FAILED") == "" {
		t.Fatal("known failures lost")
	}
}
