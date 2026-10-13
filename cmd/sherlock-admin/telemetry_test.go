package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTelemetryAdminScopeAndCAS(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	valid := [][]string{{"enroll", "--enrollment", "reviewed.json", "--expected-revision", "0", "--actor", "local-operator"}, {"status", "--cluster", "cluster-a", "--collector", "gateway-a", "--enrollment-id", "enrollment-a"}, {"revoke", "--cluster", "cluster-a", "--enrollment-id", "enrollment-a", "--expected-revision", "1", "--actor", "local-operator"}, {"rotate-key", "--cluster", "cluster-a", "--enrollment-id", "enrollment-a", "--expected-revision", "1", "--key-id", "key-2", "--public-key", base64.RawStdEncoding.EncodeToString(public), "--actor", "local-operator", "--compromised"}}
	for _, args := range valid {
		if _, err := parseTelemetryAdmin(args); err != nil {
			t.Fatal("valid command rejected", args[0])
		}
	}
	invalid := [][]string{{"status"}, {"status", "--cluster", "cluster-a", "--cluster", "other", "--collector", "gateway-a", "--enrollment-id", "enrollment-a"}, {"revoke", "--cluster", "cluster-a", "--enrollment-id", "enrollment-a", "--actor", "local-operator"}, {"status", "--cluster", "*", "--collector", "gateway-a", "--enrollment-id", "enrollment-a"}, {"enroll", "--enrollment", "a", "--expected-revision", "1", "--actor", "local-operator"}, {"status", "--cluster", "cluster-a", "--collector", "gateway-a", "--enrollment-id", "enrollment-a", "--actor", "unexpected"}}
	for _, args := range invalid {
		if _, err := parseTelemetryAdmin(args); err == nil {
			t.Fatal("unscoped or ambiguous command accepted", args)
		}
	}
}
func TestTelemetryEnrollmentStrictDocumentAndSafeErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enrollment.json")
	for _, body := range []string{`{"enrollment_id":"a","enrollment_id":"b"}`, `{"command":"private-command"}`, `{} {}`, strings.Repeat(" ", 65537)} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readTelemetryEnrollment(path); err == nil {
			t.Fatal("ambiguous enrollment accepted")
		}
	}
	var out, stderr bytes.Buffer
	if code := runTelemetryAdmin([]string{"enroll", "--enrollment", filepath.Join(dir, "private-file"), "--expected-revision", "0", "--actor", "local-operator"}, &out, &stderr); code != 2 || strings.Contains(stderr.String(), "private-file") || out.Len() != 0 {
		t.Fatal("unsafe file failure")
	}
}
