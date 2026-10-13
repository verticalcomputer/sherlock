package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCredentialKeyringFile(t *testing.T, payload string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(path, []byte(payload), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadCredentialKeyringValidatesProtectedFormat(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	path := writeCredentialKeyringFile(t, fmt.Sprintf(`{"active_version":"v1","keys":{"v1":"%s"}}`, encoded), 0o600)
	ring, err := loadCredentialKeyring(path)
	if err != nil || ring.ActiveVersion != "v1" || len(ring.Keys["v1"]) != 32 {
		t.Fatalf("ring=%v err=%v", ring, err)
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", ring, ring, ring), "BBBB") {
		t.Fatal("keyring formatted key material")
	}
}

func TestLoadCredentialKeyringRejectsWeakOrSymlinkedFile(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	weak := writeCredentialKeyringFile(t, fmt.Sprintf(`{"active_version":"v1","keys":{"v1":"%s"}}`, encoded), 0o644)
	if _, err := loadCredentialKeyring(weak); err == nil {
		t.Fatal("accepted permissive keyring")
	}
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(weak, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredentialKeyring(link); err == nil {
		t.Fatal("accepted keyring symlink")
	}
}

func TestLoadCredentialKeyringRejectsDuplicateKeys(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	path := writeCredentialKeyringFile(t, fmt.Sprintf(`{"active_version":"v1","keys":{"v1":"%s","v1":"%s"}}`, encoded, encoded), 0o600)
	if _, err := loadCredentialKeyring(path); err == nil {
		t.Fatal("accepted duplicate keyring key")
	}
}
