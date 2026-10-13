package adminmanage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func testCredentialRing(t *testing.T, version string, fill byte) *CredentialKeyring {
	t.Helper()
	ring, err := NewCredentialKeyring(version, map[string][]byte{version: bytes.Repeat([]byte{fill}, credentialKeySize)})
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

func TestCredentialCipherBindsScopeAndMetadata(t *testing.T) {
	cipher, err := newCredentialCipher(testCredentialRing(t, "v1", 0x11), bytes.NewReader(bytes.Repeat([]byte{0x22}, 128)))
	if err != nil {
		t.Fatal(err)
	}
	secrets := CredentialSecrets{SSHPassword: []byte("ssh"), SudoPassword: []byte("sudo")}
	version, nonce, ciphertext, err := cipher.seal("cluster-a", "head-a", "BCM_READ_ONLY", "user-a", "cred_a", 1, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", secrets, secrets, secrets), "sudo") {
		t.Fatal("secret formatted")
	}
	if _, err := cipher.open("cluster-b", "head-a", "BCM_READ_ONLY", "user-a", "cred_a", 1, version, nonce, ciphertext); err == nil {
		t.Fatal("cross-cluster ciphertext accepted")
	}
	if _, err := cipher.open("cluster-a", "head-a", "BCM_READ_ONLY", "user-b", "cred_a", 1, version, nonce, ciphertext); err == nil {
		t.Fatal("cross-user ciphertext accepted")
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 1
	if _, err := cipher.open("cluster-a", "head-a", "BCM_READ_ONLY", "user-a", "cred_a", 1, version, nonce, tampered); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	wrapper := struct {
		Secrets CredentialSecrets `json:"secrets"`
	}{Secrets: secrets}
	if _, err := json.Marshal(wrapper); err == nil {
		t.Fatal("secret nested JSON encoding succeeded")
	}
}

func TestPasswordlessAuthorizationContainsNoPassword(t *testing.T) {
	cipher, err := newCredentialCipher(testCredentialRing(t, "v1", 0x11), bytes.NewReader(bytes.Repeat([]byte{0x22}, 128)))
	if err != nil {
		t.Fatal(err)
	}
	version, nonce, ciphertext, err := cipher.seal("cluster-a", "head-a", "BCM_READ_ONLY_PASSWORDLESS", "user-a", "cred_a", 1, CredentialSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := cipher.open("cluster-a", "head-a", "BCM_READ_ONLY_PASSWORDLESS", "user-a", "cred_a", 1, version, nonce, ciphertext)
	if err != nil || len(secrets.SudoPassword) != 0 || len(secrets.SSHPassword) != 0 {
		t.Fatalf("invalid passwordless payload: %v", err)
	}
	if _, err := cipher.open("cluster-a", "head-a", "BCM_READ_ONLY", "user-a", "cred_a", 1, version, nonce, ciphertext); err == nil {
		t.Fatal("passwordless payload accepted as a password credential")
	}
}

func TestCredentialCipherWrongKeyAndRotationMaterial(t *testing.T) {
	first, err := newCredentialCipher(testCredentialRing(t, "v1", 0x33), bytes.NewReader(bytes.Repeat([]byte{0x44}, 128)))
	if err != nil {
		t.Fatal(err)
	}
	version, nonce, ciphertext, err := first.seal("cluster-a", "head-a", "BCM_READ_ONLY", "user-a", "cred_a", 4, CredentialSecrets{SudoPassword: []byte("sudo")})
	if err != nil {
		t.Fatal(err)
	}
	wrong, _ := newCredentialCipher(testCredentialRing(t, "v1", 0x55), bytes.NewReader(bytes.Repeat([]byte{0x66}, 128)))
	if _, err := wrong.open("cluster-a", "head-a", "BCM_READ_ONLY", "user-a", "cred_a", 4, version, nonce, ciphertext); err == nil {
		t.Fatal("wrong key accepted")
	}
	next, _ := NewCredentialKeyring("v2", map[string][]byte{"v1": bytes.Repeat([]byte{0x33}, credentialKeySize), "v2": bytes.Repeat([]byte{0x77}, credentialKeySize)})
	nextCipher, err := newCredentialCipher(next, bytes.NewReader(bytes.Repeat([]byte{0x88}, 128)))
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := first.open("cluster-a", "head-a", "BCM_READ_ONLY", "user-a", "cred_a", 4, version, nonce, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	newVersion, newNonce, newCiphertext, err := nextCipher.seal("cluster-a", "head-a", "BCM_READ_ONLY", "user-a", "cred_a", 4, secrets)
	secrets.Destroy()
	if err != nil || newVersion != "v2" {
		t.Fatalf("rotation seal version=%q err=%v", newVersion, err)
	}
	rotated, err := nextCipher.open("cluster-a", "head-a", "BCM_READ_ONLY", "user-a", "cred_a", 4, newVersion, newNonce, newCiphertext)
	if err != nil || string(rotated.SudoPassword) != "sudo" {
		t.Fatalf("rotated secret err=%v", err)
	}
	rotated.Destroy()
}

func TestCredentialKeyringRejectsTooManyKeys(t *testing.T) {
	keys := make(map[string][]byte)
	for i := 0; i < 33; i++ {
		keys[fmt.Sprintf("v%d", i)] = bytes.Repeat([]byte{byte(i)}, credentialKeySize)
	}
	if _, err := NewCredentialKeyring("v0", keys); err == nil {
		t.Fatal("accepted unbounded keyring")
	}
}
