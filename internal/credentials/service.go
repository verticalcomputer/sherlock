// Package credentials owns short-lived, single-use credential challenges.
// Plaintext values exist only inside a bounded callback and are destroyed
// immediately after use.
package credentials

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	privateKeySize       = 32
	maxEncryptedPayload  = 16 << 10
	defaultChallengeLife = 2 * time.Minute
	cleanupInterval      = time.Second
	maxIDAttempts        = 4
)

var (
	ErrNotFound = errors.New("credential challenge is unavailable")
	ErrExpired  = errors.New("credential challenge expired")
	ErrUsed     = errors.New("credential challenge was already used")
	ErrRejected = errors.New("credential submission was rejected")
)

type ID string

type Field string

const (
	FieldUsername Field = "USERNAME"
	FieldPassword Field = "PASSWORD"
	FieldOTP      Field = "OTP"
)

type Clock interface{ Now() time.Time }

// Binding ties a challenge to one already-authorized execution attempt. It
// prevents a credential submitted for one plan from being replayed for another.
type Binding struct {
	RunID      domain.DiagnosticRunID
	WorkID     domain.DiagnosticWorkID
	Attempt    int
	RunnerID   string
	PlanDigest domain.SHA256
}

type Challenge struct {
	ID        ID
	ClusterID domain.ClusterID
	Binding   Binding
	Purpose   string
	TargetIDs []string
	Fields    []Field
	PublicKey string
	ExpiresAt time.Time
}

type Submission struct {
	ClientPublicKey string
	Nonce           string
	Ciphertext      string
}

// Secret deliberately cannot be formatted or marshaled. Use exposes the bytes
// only for the duration of the callback and Destroy overwrites its storage.
type Secret struct{ bytes []byte }

func (Secret) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, "[REDACTED]") }
func (Secret) MarshalJSON() ([]byte, error) {
	return nil, errors.New("credential secrets cannot be JSON encoded")
}
func (Secret) MarshalText() ([]byte, error) {
	return nil, errors.New("credential secrets cannot be text encoded")
}

func (secret *Secret) Use(callback func([]byte) error) error {
	if secret == nil || len(secret.bytes) == 0 || callback == nil {
		return ErrRejected
	}
	return callback(secret.bytes)
}

func (secret *Secret) Destroy() {
	if secret == nil {
		return
	}
	zero(secret.bytes)
	secret.bytes = nil
}

type Acceptor interface {
	Accept(context.Context, Challenge, *Secret) error
}

type state struct {
	challenge Challenge
	private   []byte
	used      bool
}

type Service struct {
	mu       sync.Mutex
	states   map[ID]*state
	clock    Clock
	random   io.Reader
	acceptor Acceptor
	stop     chan struct{}
	done     chan struct{}
	close    sync.Once
	closed   bool
}

func NewService(clock Clock, randomSource io.Reader, acceptor Acceptor) (*Service, error) {
	if clock == nil || randomSource == nil || acceptor == nil {
		return nil, errors.New("credential clock, random source, and acceptor are required")
	}
	service := &Service{states: make(map[ID]*state), clock: clock, random: randomSource, acceptor: acceptor, stop: make(chan struct{}), done: make(chan struct{})}
	go service.cleanup()
	return service, nil
}

func (service *Service) Create(clusterID domain.ClusterID, binding Binding, purpose string, targets []string, fields []Field, lifetime time.Duration) (Challenge, error) {
	if clusterID == "" || !validBinding(binding) || purpose == "" || len(purpose) > 256 || len(targets) == 0 || len(targets) > 100 || len(fields) == 0 {
		return Challenge{}, ErrRejected
	}
	if lifetime == 0 {
		lifetime = defaultChallengeLife
	}
	if lifetime < time.Second || lifetime > 5*time.Minute {
		return Challenge{}, ErrRejected
	}
	seenTargets := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if target == "" || len(target) > 128 {
			return Challenge{}, ErrRejected
		}
		if _, duplicate := seenTargets[target]; duplicate {
			return Challenge{}, ErrRejected
		}
		seenTargets[target] = struct{}{}
	}
	seenFields := make(map[Field]struct{}, len(fields))
	for _, field := range fields {
		if field != FieldUsername && field != FieldPassword && field != FieldOTP {
			return Challenge{}, ErrRejected
		}
		if _, duplicate := seenFields[field]; duplicate {
			return Challenge{}, ErrRejected
		}
		seenFields[field] = struct{}{}
	}
	privateBytes := make([]byte, privateKeySize)
	if _, err := io.ReadFull(service.random, privateBytes); err != nil {
		zero(privateBytes)
		return Challenge{}, fmt.Errorf("create credential challenge: random source unavailable")
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		zero(privateBytes)
		return Challenge{}, ErrRejected
	}
	for range maxIDAttempts {
		idBytes := make([]byte, 18)
		if _, err := io.ReadFull(service.random, idBytes); err != nil {
			zero(privateBytes)
			return Challenge{}, fmt.Errorf("create credential challenge: random source unavailable")
		}
		id := ID("cred_" + base64.RawURLEncoding.EncodeToString(idBytes))
		challenge := Challenge{ID: id, ClusterID: clusterID, Binding: binding, Purpose: purpose, TargetIDs: append([]string(nil), targets...), Fields: append([]Field(nil), fields...), PublicKey: base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()), ExpiresAt: service.clock.Now().UTC().Add(lifetime)}
		service.mu.Lock()
		if service.closed {
			service.mu.Unlock()
			zero(privateBytes)
			return Challenge{}, ErrRejected
		}
		_, collision := service.states[id]
		if !collision {
			service.states[id] = &state{challenge: cloneChallenge(challenge), private: privateBytes}
		}
		service.mu.Unlock()
		if !collision {
			return cloneChallenge(challenge), nil
		}
	}
	zero(privateBytes)
	return Challenge{}, fmt.Errorf("create credential challenge: identifier collision")
}

// Submit consumes the challenge before decrypting. Failed or malformed
// submissions therefore cannot be retried as a decryption oracle.
func (service *Service) Submit(ctx context.Context, id ID, submission Submission) error {
	service.mu.Lock()
	entry, ok := service.states[id]
	if !ok {
		service.mu.Unlock()
		return ErrNotFound
	}
	if entry.used {
		service.mu.Unlock()
		return ErrUsed
	}
	entry.used = true
	privateBytes := append([]byte(nil), entry.private...)
	zero(entry.private)
	entry.private = nil
	challenge := cloneChallenge(entry.challenge)
	service.mu.Unlock()
	defer zero(privateBytes)
	if !service.clock.Now().Before(challenge.ExpiresAt) {
		return ErrExpired
	}
	plaintext, err := decrypt(id, privateBytes, submission)
	if err != nil {
		return ErrRejected
	}
	secret := &Secret{bytes: plaintext}
	defer secret.Destroy()
	if err := service.acceptor.Accept(ctx, challenge, secret); err != nil {
		return fmt.Errorf("deliver credential submission: %w", ErrRejected)
	}
	return nil
}

func (service *Service) DestroyExpired() int {
	now := service.clock.Now()
	removed := 0
	service.mu.Lock()
	defer service.mu.Unlock()
	for id, entry := range service.states {
		if entry.used || !now.Before(entry.challenge.ExpiresAt) {
			zero(entry.private)
			delete(service.states, id)
			removed++
		}
	}
	return removed
}

func (service *Service) Close() {
	service.close.Do(func() {
		service.mu.Lock()
		service.closed = true
		service.mu.Unlock()
		close(service.stop)
		<-service.done
		service.mu.Lock()
		defer service.mu.Unlock()
		for id, entry := range service.states {
			zero(entry.private)
			delete(service.states, id)
		}
	})
}

func (service *Service) cleanup() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	defer close(service.done)
	for {
		select {
		case <-ticker.C:
			service.DestroyExpired()
		case <-service.stop:
			return
		}
	}
}

func decrypt(id ID, privateBytes []byte, submission Submission) ([]byte, error) {
	if len(submission.ClientPublicKey) != base64.RawURLEncoding.EncodedLen(privateKeySize) ||
		len(submission.Nonce) != base64.RawURLEncoding.EncodedLen(12) ||
		len(submission.Ciphertext) == 0 || len(submission.Ciphertext) > base64.RawURLEncoding.EncodedLen(maxEncryptedPayload) {
		return nil, ErrRejected
	}
	clientBytes, err := base64.RawURLEncoding.DecodeString(submission.ClientPublicKey)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.RawURLEncoding.DecodeString(submission.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(submission.Ciphertext)
	if err != nil || len(ciphertext) == 0 || len(ciphertext) > maxEncryptedPayload {
		return nil, ErrRejected
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return nil, err
	}
	clientKey, err := ecdh.X25519().NewPublicKey(clientBytes)
	if err != nil {
		return nil, err
	}
	shared, err := privateKey.ECDH(clientKey)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256(append(shared, []byte(id)...))
	zero(shared)
	block, err := aes.NewCipher(key[:])
	zero(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != aead.NonceSize() {
		return nil, ErrRejected
	}
	return aead.Open(nil, nonce, ciphertext, []byte(id))
}

func cloneChallenge(challenge Challenge) Challenge {
	challenge.TargetIDs = append([]string(nil), challenge.TargetIDs...)
	challenge.Fields = append([]Field(nil), challenge.Fields...)
	return challenge
}

func validBinding(binding Binding) bool {
	return safeToken(string(binding.RunID)) && safeToken(string(binding.WorkID)) && binding.Attempt >= 1 && binding.Attempt <= 3 && safeToken(binding.RunnerID) && binding.PlanDigest != (domain.SHA256{})
}

func safeToken(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || (index > 0 && (character == '.' || character == '_' || character == '-')) {
			continue
		}
		return false
	}
	return true
}

// SealForChallenge is intended for API clients and tests. It encrypts one
// opaque credential payload to the challenge public key.
func SealForChallenge(challenge Challenge, plaintext []byte) (Submission, error) {
	serverBytes, err := base64.RawURLEncoding.DecodeString(challenge.PublicKey)
	if err != nil {
		return Submission{}, err
	}
	serverKey, err := ecdh.X25519().NewPublicKey(serverBytes)
	if err != nil {
		return Submission{}, err
	}
	clientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Submission{}, err
	}
	shared, err := clientKey.ECDH(serverKey)
	if err != nil {
		return Submission{}, err
	}
	key := sha256.Sum256(append(shared, []byte(challenge.ID)...))
	zero(shared)
	block, err := aes.NewCipher(key[:])
	zero(key[:])
	if err != nil {
		return Submission{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Submission{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Submission{}, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, []byte(challenge.ID))
	return Submission{ClientPublicKey: base64.RawURLEncoding.EncodeToString(clientKey.PublicKey().Bytes()), Nonce: base64.RawURLEncoding.EncodeToString(nonce), Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext)}, nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
