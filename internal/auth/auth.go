// Package auth owns public API-key credentials and cluster-scoped principals.
// It deliberately has no HTTP dependencies.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const keyPrefix = "shk_live_"

var (
	ErrUnauthenticated = errors.New("API key is invalid or unavailable")
	ErrForbidden       = errors.New("principal is not authorized")
	ErrKeyNotFound     = errors.New("API key does not exist")
)

type Capability string

const (
	CapabilityClusterRead           Capability = "cluster:read"
	CapabilityTelemetryRead         Capability = "telemetry:read"
	CapabilityIncidentsRead         Capability = "incidents:read"
	CapabilityIncidentsWrite        Capability = "incidents:write"
	CapabilityInvestigationsRead    Capability = "investigations:read"
	CapabilityInvestigationsRun     Capability = "investigations:run"
	CapabilityDiagnosticsPrivileged Capability = "diagnostics:privileged"
	CapabilityEvidenceRaw           Capability = "evidence:raw"
	CapabilityConfigurationRead     Capability = "configuration:read"
	CapabilityConfigurationWrite    Capability = "configuration:write"
	CapabilityAuditRead             Capability = "audit:read"
)

var supportedCapabilities = map[Capability]struct{}{
	CapabilityClusterRead: {}, CapabilityTelemetryRead: {}, CapabilityIncidentsRead: {},
	CapabilityIncidentsWrite: {}, CapabilityInvestigationsRead: {}, CapabilityInvestigationsRun: {},
	CapabilityDiagnosticsPrivileged: {}, CapabilityEvidenceRaw: {}, CapabilityConfigurationRead: {},
	CapabilityConfigurationWrite: {}, CapabilityAuditRead: {},
}

func ParseCapability(value string) (Capability, error) {
	capability := Capability(value)
	if _, ok := supportedCapabilities[capability]; !ok {
		return "", fmt.Errorf("unsupported API-key capability")
	}
	return capability, nil
}

func AllCapabilities() []Capability {
	result := make([]Capability, 0, len(supportedCapabilities))
	for capability := range supportedCapabilities {
		result = append(result, capability)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

type Key struct {
	PublicID     string
	ClusterID    domain.ClusterID
	Label        string
	Capabilities []Capability
	CreatedAt    time.Time
	ExpiresAt    time.Time
	LastUsedAt   *time.Time
	RevokedAt    *time.Time
}

type StoredKey struct {
	Key
	SecretHash [sha256.Size]byte
}

type Principal struct {
	KeyID        string
	ClusterID    domain.ClusterID
	Label        string
	Capabilities []Capability
}

func (p Principal) Has(capability Capability) bool {
	for _, candidate := range p.Capabilities {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(capability)) == 1 {
			return true
		}
	}
	return false
}

func (p Principal) Authorize(clusterID domain.ClusterID, capability Capability) error {
	if p.ClusterID == "" || clusterID == "" || subtle.ConstantTimeCompare([]byte(p.ClusterID), []byte(clusterID)) != 1 || !p.Has(capability) {
		return ErrForbidden
	}
	return nil
}

// PlaintextKey intentionally implements neither fmt.Stringer nor text/JSON
// marshaling. WriteOnce is the only way for an administrator to reveal it and
// destroys the in-memory bytes immediately afterward.
type PlaintextKey struct {
	bytes []byte
}

func (*PlaintextKey) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}

func (*PlaintextKey) MarshalJSON() ([]byte, error) {
	return nil, errors.New("plaintext API keys cannot be JSON encoded")
}

func (*PlaintextKey) MarshalText() ([]byte, error) {
	return nil, errors.New("plaintext API keys cannot be text encoded")
}

func (k *PlaintextKey) WriteOnce(writer io.Writer) error {
	if k == nil || len(k.bytes) == 0 {
		return errors.New("plaintext API key is unavailable")
	}
	_, err := writer.Write(k.bytes)
	k.Destroy()
	return err
}

func (k *PlaintextKey) Destroy() {
	if k == nil {
		return
	}
	for index := range k.bytes {
		k.bytes[index] = 0
	}
	k.bytes = nil
}

type IssuedKey struct {
	Key       Key
	Plaintext *PlaintextKey
}

type Store interface {
	CreateKey(context.Context, StoredKey) error
	FindKey(context.Context, string) (StoredKey, error)
	MarkKeyUsed(context.Context, string, time.Time) error
	ListKeys(context.Context, domain.ClusterID) ([]Key, error)
	RevokeKey(context.Context, domain.ClusterID, string, time.Time) (bool, error)
}

type Clock interface {
	Now() time.Time
}

type Service struct {
	store   Store
	clock   Clock
	random  io.Reader
	hashKey []byte
}

func NewService(store Store, clock Clock, random io.Reader, hashKey []byte) (*Service, error) {
	if store == nil || clock == nil || random == nil {
		return nil, errors.New("API-key store, clock, and random source are required")
	}
	if len(hashKey) < sha256.Size {
		return nil, errors.New("API-key hash key must contain at least 32 bytes")
	}
	keyCopy := append([]byte(nil), hashKey...)
	return &Service{store: store, clock: clock, random: random, hashKey: keyCopy}, nil
}

func (s *Service) Close() {
	for index := range s.hashKey {
		s.hashKey[index] = 0
	}
	s.hashKey = nil
}

func (s *Service) CreateKey(ctx context.Context, clusterID domain.ClusterID, label string, capabilities []Capability, expiresAt time.Time) (IssuedKey, error) {
	now := s.clock.Now().UTC()
	capabilities, err := validateMetadata(clusterID, label, capabilities, expiresAt, now)
	if err != nil {
		return IssuedKey{}, err
	}
	publicBytes := make([]byte, 16)
	secretBytes := make([]byte, 32)
	if _, err := io.ReadFull(s.random, publicBytes); err != nil {
		return IssuedKey{}, errors.New("generate API-key identifier")
	}
	if _, err := io.ReadFull(s.random, secretBytes); err != nil {
		return IssuedKey{}, errors.New("generate API-key secret")
	}
	publicID := base64.RawURLEncoding.EncodeToString(publicBytes)
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	plaintext := []byte(keyPrefix + publicID + "." + secret)
	for index := range secretBytes {
		secretBytes[index] = 0
	}
	record := StoredKey{Key: Key{PublicID: publicID, ClusterID: clusterID, Label: label, Capabilities: capabilities, CreatedAt: now, ExpiresAt: expiresAt.UTC()}}
	record.SecretHash = s.hash(publicID, secret)
	if err := s.store.CreateKey(ctx, record); err != nil {
		for index := range plaintext {
			plaintext[index] = 0
		}
		return IssuedKey{}, fmt.Errorf("create API key: %w", err)
	}
	return IssuedKey{Key: record.Key, Plaintext: &PlaintextKey{bytes: plaintext}}, nil
}

func (s *Service) Authenticate(ctx context.Context, plaintext []byte) (Principal, error) {
	// Authentication consumes the caller-owned buffer so transport boundaries
	// cannot accidentally retain the credential after verification.
	defer destroyBytes(plaintext)
	publicID, secret, validFormat := parsePlaintext(plaintext)
	if !validFormat {
		return Principal{}, ErrUnauthenticated
	}
	record, err := s.store.FindKey(ctx, publicID)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			// Still perform a keyed comparison so unknown identifiers follow the
			// same local verification path as known identifiers.
			dummy := s.hash(publicID, secret)
			_ = subtle.ConstantTimeCompare(dummy[:], make([]byte, sha256.Size))
			return Principal{}, ErrUnauthenticated
		}
		return Principal{}, errors.New("authenticate API key")
	}
	candidate := s.hash(publicID, secret)
	secretMatches := subtle.ConstantTimeCompare(candidate[:], record.SecretHash[:]) == 1
	now := s.clock.Now().UTC()
	available := record.RevokedAt == nil && record.ExpiresAt.After(now)
	if !secretMatches || !available {
		return Principal{}, ErrUnauthenticated
	}
	if err := s.store.MarkKeyUsed(ctx, record.PublicID, now); err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return Principal{}, ErrUnauthenticated
		}
		return Principal{}, errors.New("authenticate API key")
	}
	return Principal{KeyID: record.PublicID, ClusterID: record.ClusterID, Label: record.Label, Capabilities: append([]Capability(nil), record.Capabilities...)}, nil
}

func (s *Service) ListKeys(ctx context.Context, clusterID domain.ClusterID) ([]Key, error) {
	if clusterID == "" {
		return nil, errors.New("cluster identifier is required")
	}
	return s.store.ListKeys(ctx, clusterID)
}

func (s *Service) RevokeKey(ctx context.Context, clusterID domain.ClusterID, publicID string) error {
	if clusterID == "" || !validPublicID(publicID) {
		return errors.New("cluster and API-key identifiers are required")
	}
	revoked, err := s.store.RevokeKey(ctx, clusterID, publicID, s.clock.Now().UTC())
	if err != nil {
		return fmt.Errorf("revoke API key: %w", err)
	}
	if !revoked {
		return ErrKeyNotFound
	}
	return nil
}

func validateMetadata(clusterID domain.ClusterID, label string, capabilities []Capability, expiresAt, now time.Time) ([]Capability, error) {
	if clusterID == "" || len(label) < 1 || len(label) > 128 || expiresAt.IsZero() || !expiresAt.After(now) {
		return nil, errors.New("cluster, safe label, and future expiry are required")
	}
	for _, character := range label {
		if unicode.IsControl(character) {
			return nil, errors.New("API-key label contains a control character")
		}
	}
	if len(capabilities) == 0 || len(capabilities) > len(supportedCapabilities) {
		return nil, errors.New("at least one supported API-key capability is required")
	}
	seen := make(map[Capability]struct{}, len(capabilities))
	result := make([]Capability, 0, len(capabilities))
	for _, capability := range capabilities {
		if _, ok := supportedCapabilities[capability]; !ok {
			return nil, errors.New("unsupported API-key capability")
		}
		if _, duplicate := seen[capability]; duplicate {
			return nil, errors.New("API-key capabilities must be unique")
		}
		seen[capability] = struct{}{}
		result = append(result, capability)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, nil
}

func parsePlaintext(plaintext []byte) (string, string, bool) {
	if len(plaintext) != len(keyPrefix)+22+1+43 || !strings.HasPrefix(string(plaintext), keyPrefix) {
		return "", "", false
	}
	remainder := string(plaintext[len(keyPrefix):])
	separator := strings.IndexByte(remainder, '.')
	if separator != 22 || strings.IndexByte(remainder[separator+1:], '.') >= 0 {
		return "", "", false
	}
	publicID, secret := remainder[:separator], remainder[separator+1:]
	if !validPublicID(publicID) {
		return "", "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(decoded) != 32 {
		return "", "", false
	}
	for index := range decoded {
		decoded[index] = 0
	}
	return publicID, secret, true
}

func validPublicID(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(value) == 22 && len(decoded) == 16
}

func (s *Service) hash(publicID, secret string) [sha256.Size]byte {
	mac := hmac.New(sha256.New, s.hashKey)
	_, _ = mac.Write([]byte(publicID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(secret))
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func destroyBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
