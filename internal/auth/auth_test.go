package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

type memoryStore struct {
	keys map[string]StoredKey
	used map[string]time.Time
}

func newMemoryStore() *memoryStore {
	return &memoryStore{keys: make(map[string]StoredKey), used: make(map[string]time.Time)}
}

func (store *memoryStore) CreateKey(_ context.Context, key StoredKey) error {
	if _, exists := store.keys[key.PublicID]; exists {
		return errors.New("duplicate")
	}
	store.keys[key.PublicID] = key
	return nil
}

func (store *memoryStore) FindKey(_ context.Context, publicID string) (StoredKey, error) {
	key, exists := store.keys[publicID]
	if !exists {
		return StoredKey{}, ErrKeyNotFound
	}
	return key, nil
}

func (store *memoryStore) MarkKeyUsed(_ context.Context, publicID string, usedAt time.Time) error {
	store.used[publicID] = usedAt
	return nil
}

func (store *memoryStore) ListKeys(_ context.Context, clusterID domain.ClusterID) ([]Key, error) {
	var keys []Key
	for _, key := range store.keys {
		if key.ClusterID == clusterID {
			keys = append(keys, key.Key)
		}
	}
	return keys, nil
}

func (store *memoryStore) RevokeKey(_ context.Context, clusterID domain.ClusterID, publicID string, revokedAt time.Time) (bool, error) {
	key, exists := store.keys[publicID]
	if !exists || key.ClusterID != clusterID {
		return false, nil
	}
	key.RevokedAt = &revokedAt
	store.keys[publicID] = key
	return true, nil
}

func TestCreateAuthenticateAndAuthorizeAPIKey(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	random := bytes.NewReader(bytes.Repeat([]byte{0x5a}, 96))
	service, err := NewService(store, fixedClock{now}, random, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	issued, err := service.CreateKey(context.Background(), "cluster-a", "global backend", []Capability{CapabilityTelemetryRead, CapabilityClusterRead}, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var plaintext bytes.Buffer
	if err := issued.Plaintext.WriteOnce(&plaintext); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plaintext.String(), "shk_live_") || len(plaintext.String()) != len(keyPrefix)+22+1+43 {
		t.Fatalf("unexpected API-key form")
	}
	if err := issued.Plaintext.WriteOnce(&bytes.Buffer{}); err == nil {
		t.Fatal("plaintext API key could be revealed twice")
	}
	stored := store.keys[issued.Key.PublicID]
	if bytes.Contains(stored.SecretHash[:], plaintext.Bytes()) || bytes.Contains(plaintext.Bytes(), stored.SecretHash[:]) {
		t.Fatal("stored representation contains plaintext")
	}
	principal, err := service.Authenticate(context.Background(), plaintext.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if principal.KeyID != issued.Key.PublicID || principal.ClusterID != "cluster-a" || principal.Label != "global backend" {
		t.Fatalf("unexpected principal: %+v", principal)
	}
	if err := principal.Authorize("cluster-a", CapabilityTelemetryRead); err != nil {
		t.Fatalf("expected authorization: %v", err)
	}
	if !errors.Is(principal.Authorize("cluster-b", CapabilityTelemetryRead), ErrForbidden) {
		t.Fatal("cross-cluster authorization did not fail closed")
	}
	if !errors.Is(principal.Authorize("cluster-a", CapabilityAuditRead), ErrForbidden) {
		t.Fatal("missing capability did not fail closed")
	}
	if store.used[issued.Key.PublicID] != now {
		t.Fatal("successful use was not recorded")
	}
	if !bytes.Equal(plaintext.Bytes(), make([]byte, plaintext.Len())) {
		t.Fatal("authentication did not destroy the plaintext input buffer")
	}
}

func TestPlaintextKeyCannotBeFormattedOrEncoded(t *testing.T) {
	plaintext := &PlaintextKey{bytes: []byte("shk_live_secret")}
	for _, formatted := range []string{fmt.Sprintf("%v", plaintext), fmt.Sprintf("%#v", plaintext), fmt.Sprintf("%s", plaintext), fmt.Sprintf("%x", plaintext)} {
		if formatted != "[REDACTED]" {
			t.Fatalf("plaintext was formatable: %q", formatted)
		}
	}
	if _, err := json.Marshal(plaintext); err == nil {
		t.Fatal("plaintext API key was JSON encodable")
	}
}

func TestRotationExpiryRevocationAndSafeFailures(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	randomBytes := append(bytes.Repeat([]byte{0x17}, 48), bytes.Repeat([]byte{0x18}, 48)...)
	service, err := NewService(store, fixedClock{now}, bytes.NewReader(randomBytes), bytes.Repeat([]byte{0x29}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	create := func(label string, expiry time.Time) (IssuedKey, []byte) {
		issued, err := service.CreateKey(context.Background(), "cluster-a", label, []Capability{CapabilityClusterRead}, expiry)
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err := issued.Plaintext.WriteOnce(&output); err != nil {
			t.Fatal(err)
		}
		return issued, output.Bytes()
	}
	oldKey, oldPlaintext := create("old", now.Add(time.Hour))
	newKey, newPlaintext := create("new", now.Add(2*time.Hour))
	for _, plaintext := range [][]byte{oldPlaintext, newPlaintext} {
		if _, err := service.Authenticate(context.Background(), append([]byte(nil), plaintext...)); err != nil {
			t.Fatalf("overlapping rotation key was rejected: %v", err)
		}
	}
	if err := service.RevokeKey(context.Background(), "cluster-a", oldKey.Key.PublicID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(context.Background(), oldPlaintext); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked key returned unsafe or unexpected error: %v", err)
	}
	wrongSecret := append([]byte(nil), newPlaintext...)
	wrongSecret[len(wrongSecret)-1] = 'x'
	if _, err := service.Authenticate(context.Background(), wrongSecret); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("wrong secret returned unsafe or unexpected error: %v", err)
	}
	if _, err := service.Authenticate(context.Background(), []byte("not-a-key")); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("malformed key returned unsafe or unexpected error: %v", err)
	}
	unknown := []byte("shk_live_AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if _, err := service.Authenticate(context.Background(), unknown); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unknown key returned unsafe or unexpected error: %v", err)
	}
	expiredRecord := store.keys[newKey.Key.PublicID]
	expiredRecord.ExpiresAt = now
	store.keys[newKey.Key.PublicID] = expiredRecord
	if _, err := service.Authenticate(context.Background(), append([]byte(nil), newPlaintext...)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expired key returned unsafe or unexpected error: %v", err)
	}
	if _, err := service.CreateKey(context.Background(), "cluster-a", "expired", []Capability{CapabilityClusterRead}, now); err == nil {
		t.Fatal("non-future expiry was accepted")
	}
	_ = newKey
}

func TestCapabilitiesAreClosedAndMetadataIsBounded(t *testing.T) {
	if _, err := ParseCapability("administrator"); err == nil {
		t.Fatal("unknown capability was accepted")
	}
	if len(AllCapabilities()) != 11 {
		t.Fatalf("unexpected capability count: %d", len(AllCapabilities()))
	}
	now := time.Now().UTC()
	store := newMemoryStore()
	service, err := NewService(store, fixedClock{now}, bytes.NewReader(bytes.Repeat([]byte{1}, 64)), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if _, err := service.CreateKey(context.Background(), "cluster-a", "unsafe\nlabel", []Capability{CapabilityClusterRead}, now.Add(time.Hour)); err == nil {
		t.Fatal("control character in label was accepted")
	}
	if _, err := service.CreateKey(context.Background(), "cluster-a", "duplicate", []Capability{CapabilityClusterRead, CapabilityClusterRead}, now.Add(time.Hour)); err == nil {
		t.Fatal("duplicate capability was accepted")
	}
}

func TestServiceRequiresHighEntropyHashKey(t *testing.T) {
	if _, err := NewService(newMemoryStore(), fixedClock{}, bytes.NewReader(nil), []byte("short")); err == nil {
		t.Fatal("short hash key was accepted")
	}
}
