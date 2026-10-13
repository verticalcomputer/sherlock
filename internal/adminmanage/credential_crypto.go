package adminmanage

import (
	"crypto/aes"
	cipherpkg "crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

const (
	credentialKeySize      = 32
	credentialNonceSize    = 12
	credentialMaxPlaintext = 8 << 10
)

var (
	ErrCredentialKeyUnavailable    = errors.New("credential encryption key is unavailable")
	ErrCredentialCiphertextInvalid = errors.New("credential ciphertext is invalid")
)

// CredentialKeyring contains the active key and retained historical keys.
// Keys are deployment configuration and must never be persisted in PostgreSQL.
type CredentialKeyring struct {
	ActiveVersion string
	Keys          map[string][]byte
}

func (ring CredentialKeyring) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}
func (ring CredentialKeyring) MarshalJSON() ([]byte, error) {
	return nil, errors.New("credential keyring cannot be JSON encoded")
}
func (ring CredentialKeyring) MarshalText() ([]byte, error) {
	return nil, errors.New("credential keyring cannot be text encoded")
}

func NewCredentialKeyring(active string, keys map[string][]byte) (*CredentialKeyring, error) {
	active = strings.TrimSpace(active)
	if !validCredentialKeyVersion(active) || len(keys) == 0 || len(keys) > 32 {
		return nil, ErrCredentialKeyUnavailable
	}
	cloned := make(map[string][]byte, len(keys))
	for version, key := range keys {
		if !validCredentialKeyVersion(version) || len(key) != credentialKeySize {
			return nil, ErrCredentialKeyUnavailable
		}
		cloned[version] = append([]byte(nil), key...)
	}
	if _, ok := cloned[active]; !ok {
		return nil, ErrCredentialKeyUnavailable
	}
	return &CredentialKeyring{ActiveVersion: active, Keys: cloned}, nil
}

func (ring *CredentialKeyring) clone() *CredentialKeyring {
	if ring == nil {
		return nil
	}
	keys := make(map[string][]byte, len(ring.Keys))
	for version, key := range ring.Keys {
		keys[version] = append([]byte(nil), key...)
	}
	return &CredentialKeyring{ActiveVersion: ring.ActiveVersion, Keys: keys}
}

func (ring *CredentialKeyring) clear() {
	if ring == nil {
		return
	}
	for version, key := range ring.Keys {
		clearBytes(key)
		delete(ring.Keys, version)
	}
	ring.ActiveVersion = ""
}

// Destroy clears key material owned by a configuration handoff. The active
// store keeps its own bounded clone and does not call this on the live ring.
func (ring *CredentialKeyring) Destroy() {
	if ring != nil {
		ring.clear()
	}
}

type credentialSecretPayload struct {
	SSHPassword  string `json:"ssh_password,omitempty"`
	SudoPassword string `json:"sudo_password"`
}

// CredentialSecrets is intentionally only returned by the trusted backend
// resolver. It has no JSON/text representation and callers must Destroy it.
type CredentialSecrets struct {
	SSHPassword  []byte
	SudoPassword []byte
}

func (secrets CredentialSecrets) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}
func (secrets CredentialSecrets) MarshalJSON() ([]byte, error) {
	return nil, errors.New("credential secrets cannot be JSON encoded")
}
func (secrets CredentialSecrets) MarshalText() ([]byte, error) {
	return nil, errors.New("credential secrets cannot be text encoded")
}

func (secrets *CredentialSecrets) Destroy() {
	if secrets == nil {
		return
	}
	clearBytes(secrets.SSHPassword)
	clearBytes(secrets.SudoPassword)
	secrets.SSHPassword = nil
	secrets.SudoPassword = nil
}

type credentialCipher struct {
	mu     sync.RWMutex
	ring   *CredentialKeyring
	random io.Reader
}

func newCredentialCipher(ring *CredentialKeyring, random io.Reader) (*credentialCipher, error) {
	if ring == nil || random == nil {
		return nil, ErrCredentialKeyUnavailable
	}
	return &credentialCipher{ring: ring.clone(), random: random}, nil
}

func (cipher *credentialCipher) active() (string, []byte, error) {
	cipher.mu.RLock()
	defer cipher.mu.RUnlock()
	key := cipher.ring.Keys[cipher.ring.ActiveVersion]
	if len(key) != credentialKeySize {
		return "", nil, ErrCredentialKeyUnavailable
	}
	return cipher.ring.ActiveVersion, append([]byte(nil), key...), nil
}

func (cipher *credentialCipher) key(version string) ([]byte, error) {
	cipher.mu.RLock()
	defer cipher.mu.RUnlock()
	key := cipher.ring.Keys[version]
	if len(key) != credentialKeySize {
		return nil, ErrCredentialKeyUnavailable
	}
	return append([]byte(nil), key...), nil
}

func (cipher *credentialCipher) seal(clusterID, host, purpose, username, credentialID string, credentialVersion int64, secrets CredentialSecrets) (version string, nonce, ciphertext []byte, err error) {
	version, key, err := cipher.active()
	if err != nil {
		return "", nil, nil, err
	}
	defer clearBytes(key)
	payload, err := json.Marshal(credentialSecretPayload{SSHPassword: string(secrets.SSHPassword), SudoPassword: string(secrets.SudoPassword)})
	defer clearBytes(payload)
	if err != nil || len(payload) == 0 || len(payload) > credentialMaxPlaintext {
		return "", nil, nil, ErrCredentialCiphertextInvalid
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", nil, nil, ErrCredentialCiphertextInvalid
	}
	aead, err := cipherpkg.NewGCM(block)
	if err != nil {
		return "", nil, nil, ErrCredentialCiphertextInvalid
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(cipher.random, nonce); err != nil {
		clearBytes(nonce)
		return "", nil, nil, ErrCredentialCiphertextInvalid
	}
	ciphertext = aead.Seal(nil, nonce, payload, credentialAAD(clusterID, host, purpose, username, credentialID, credentialVersion, version))
	return version, nonce, ciphertext, nil
}

func (cipher *credentialCipher) open(clusterID, host, purpose, username, credentialID string, credentialVersion int64, version string, nonce, ciphertext []byte) (CredentialSecrets, error) {
	if len(nonce) != credentialNonceSize || len(ciphertext) < 16 || len(ciphertext) > credentialMaxPlaintext+32 {
		return CredentialSecrets{}, ErrCredentialCiphertextInvalid
	}
	key, err := cipher.key(version)
	if err != nil {
		return CredentialSecrets{}, err
	}
	defer clearBytes(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return CredentialSecrets{}, ErrCredentialCiphertextInvalid
	}
	aead, err := cipherpkg.NewGCM(block)
	if err != nil || len(nonce) != aead.NonceSize() {
		return CredentialSecrets{}, ErrCredentialCiphertextInvalid
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, credentialAAD(clusterID, host, purpose, username, credentialID, credentialVersion, version))
	if err != nil {
		return CredentialSecrets{}, ErrCredentialCiphertextInvalid
	}
	var payload credentialSecretPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil || (purpose == "BCM_READ_ONLY" && payload.SudoPassword == "") || (purpose == "BCM_READ_ONLY_PASSWORDLESS" && (payload.SudoPassword != "" || payload.SSHPassword != "")) || len(payload.SSHPassword) > credentialMaxPlaintext || len(payload.SudoPassword) > credentialMaxPlaintext {
		clearBytes(plaintext)
		return CredentialSecrets{}, ErrCredentialCiphertextInvalid
	}
	clearBytes(plaintext)
	return CredentialSecrets{SSHPassword: []byte(payload.SSHPassword), SudoPassword: []byte(payload.SudoPassword)}, nil
}

func credentialAAD(clusterID, host, purpose, username, credentialID string, credentialVersion int64, keyVersion string) []byte {
	binding := struct {
		Format            string `json:"format"`
		ClusterID         string `json:"cluster_id"`
		Host              string `json:"host"`
		Purpose           string `json:"purpose"`
		Username          string `json:"username"`
		CredentialID      string `json:"credential_id"`
		CredentialVersion int64  `json:"credential_version"`
		KeyVersion        string `json:"key_version"`
	}{"sherlock-credential-onboarding-v1", clusterID, host, purpose, username, credentialID, credentialVersion, keyVersion}
	value, _ := json.Marshal(binding)
	return value
}

func validCredentialKeyVersion(version string) bool {
	if len(version) == 0 || len(version) > 64 {
		return false
	}
	for _, r := range version {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r) {
			continue
		}
		return false
	}
	return true
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
