package collectorpop

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestCanonicalRequestIsStableAndBound(t *testing.T) {
	digest := sha256.Sum256([]byte("body"))
	canonical, err := CanonicalRequest("POST", "/collector/v1/heartbeat", "a=1", "CONTROL.EXAMPLE:443", "1", "correlation", "2026-09-05T10:00:00Z", digest)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"sherlock-collector-pop-v1", "control.example", "correlation", "a=1"} {
		if !strings.Contains(string(canonical), required) {
			t.Fatalf("canonical request missing %q", required)
		}
	}
}

func TestCanonicalRequestRejectsLineBreaks(t *testing.T) {
	if _, err := CanonicalRequest("GET", "/", "", "control.example", "1", "bad\nvalue", "time", [32]byte{}); err == nil {
		t.Fatal("expected line-break rejection")
	}
}
