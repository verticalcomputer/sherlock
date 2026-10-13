package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

const credentialKeyringMaximumBytes = 64 << 10

type CredentialKeyringConfig struct {
	ActiveVersion string
	Keys          map[string][]byte
}

func (config CredentialKeyringConfig) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}
func (config CredentialKeyringConfig) MarshalJSON() ([]byte, error) {
	return nil, errors.New("credential keyring cannot be JSON encoded")
}

func loadCredentialKeyring(path string) (CredentialKeyringConfig, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return CredentialKeyringConfig{}, fmt.Errorf("inspect credential keyring: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return CredentialKeyringConfig{}, errors.New("credential keyring must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return CredentialKeyringConfig{}, errors.New("credential keyring permissions must be 0600 or stricter")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && uint32(stat.Uid) != uint32(os.Getuid()) {
		return CredentialKeyringConfig{}, errors.New("credential keyring must be owned by the service user")
	}
	if info.Size() <= 0 || info.Size() > credentialKeyringMaximumBytes {
		return CredentialKeyringConfig{}, errors.New("credential keyring exceeds its size limit")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return CredentialKeyringConfig{}, fmt.Errorf("open credential keyring: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || openedInfo == nil {
		return CredentialKeyringConfig{}, errors.New("credential keyring changed during open")
	}
	openedStat, openedStatOK := openedInfo.Sys().(*syscall.Stat_t)
	originalStat, originalStatOK := info.Sys().(*syscall.Stat_t)
	if !openedInfo.Mode().IsRegular() || openedInfo.Size() != info.Size() || openedInfo.Mode().Perm()&0o077 != 0 || !os.SameFile(info, openedInfo) || (openedStatOK && originalStatOK && uint32(openedStat.Uid) != uint32(originalStat.Uid)) {
		return CredentialKeyringConfig{}, errors.New("credential keyring changed during open")
	}
	payload, err := io.ReadAll(io.LimitReader(file, credentialKeyringMaximumBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > credentialKeyringMaximumBytes {
		return CredentialKeyringConfig{}, errors.New("read credential keyring exceeded its size limit")
	}
	defer clearConfigBytes(payload)
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return CredentialKeyringConfig{}, errors.New("credential keyring JSON contains duplicate keys")
	}
	var document struct {
		ActiveVersion string            `json:"active_version"`
		Keys          map[string]string `json:"keys"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return CredentialKeyringConfig{}, errors.New("credential keyring JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return CredentialKeyringConfig{}, errors.New("credential keyring contains trailing JSON")
	}
	if !validCredentialKeyVersionConfig(document.ActiveVersion) || len(document.Keys) == 0 || len(document.Keys) > 32 {
		return CredentialKeyringConfig{}, errors.New("credential keyring versions are invalid")
	}
	keys := make(map[string][]byte, len(document.Keys))
	valid := false
	defer func() {
		if !valid {
			for _, key := range keys {
				clearConfigBytes(key)
			}
		}
	}()
	for version, encoded := range document.Keys {
		if !validCredentialKeyVersionConfig(version) {
			return CredentialKeyringConfig{}, errors.New("credential keyring version is invalid")
		}
		key, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil {
			key, err = base64.StdEncoding.Strict().DecodeString(encoded)
		}
		if err != nil || len(key) != 32 {
			return CredentialKeyringConfig{}, errors.New("credential keyring key must be 32 bytes of base64")
		}
		keys[version] = key
	}
	if _, ok := keys[document.ActiveVersion]; !ok {
		return CredentialKeyringConfig{}, errors.New("credential keyring active version is missing")
	}
	valid = true
	return CredentialKeyringConfig{ActiveVersion: document.ActiveVersion, Keys: keys}, nil
}

// LoadCredentialKeyringFile loads the protected external keyring for a
// maintenance command. Callers must clear the returned key bytes after
// handing a cloned copy to the trusted store.
func LoadCredentialKeyringFile(path string) (CredentialKeyringConfig, error) {
	if strings.TrimSpace(path) == "" {
		return CredentialKeyringConfig{}, errors.New("credential keyring path is required")
	}
	return loadCredentialKeyring(path)
}

func rejectDuplicateJSONKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := walkCredentialJSON(decoder); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func walkCredentialJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			rawKey, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := rawKey.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate key %q", key)
			}
			seen[key] = struct{}{}
			if err := walkCredentialJSON(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := walkCredentialJSON(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func clearConfigBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func validCredentialKeyVersionConfig(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r) {
			continue
		}
		return false
	}
	return true
}
