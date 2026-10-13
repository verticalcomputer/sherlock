package collectorcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

var (
	ErrBootstrapUnavailable = errors.New("collector bootstrap key is invalid, expired, or already consumed")
	ErrCollectorInactive    = errors.New("collector is not active")
)

type Clock interface {
	Now() time.Time
}

type IDGenerator interface {
	NewID() (string, error)
}

type BootstrapGrant struct {
	BootstrapKeyID string
	ClusterID      domain.ClusterID
	ExpiresAt      time.Time
}

type CollectorMetadata struct {
	DisplayName     string
	Version         string
	BuildCommit     string
	ProtocolMin     int
	ProtocolMax     int
	OperatingSystem string
	Architecture    string
}

type IssuedIdentity struct {
	CertificatePEM []byte
	CAChainPEM     []byte
	Serial         string
	Fingerprint    [32]byte
	NotBefore      time.Time
	NotAfter       time.Time
}

type AuthenticatedIdentity struct {
	CollectorID domain.CollectorID
	ClusterID   domain.ClusterID
}

type IdentityAuthenticator interface {
	AuthenticateCollectorIdentity(context.Context, string, [32]byte) (AuthenticatedIdentity, error)
}

type IdentityStore interface {
	CreateBootstrapKey(context.Context, string, domain.ClusterID, [32]byte, time.Time) error
	FindBootstrapGrant(context.Context, [32]byte) (BootstrapGrant, error)
	ConsumeBootstrapAndEnroll(context.Context, BootstrapGrant, [32]byte, domain.CollectorID, CollectorMetadata, IssuedIdentity) error
	ActiveCollectorCluster(context.Context, domain.CollectorID) (domain.ClusterID, error)
	RecordRenewedIdentity(context.Context, domain.CollectorID, IssuedIdentity) error
	RevokeCollector(context.Context, domain.CollectorID) error
}

type CertificateIssuer interface {
	Issue(domain.ClusterID, domain.CollectorID, []byte, time.Time, time.Duration) (IssuedIdentity, error)
}

type IdentityService struct {
	store       IdentityStore
	issuer      CertificateIssuer
	clock       Clock
	ids         IDGenerator
	random      io.Reader
	identityTTL time.Duration
}

func NewIdentityService(store IdentityStore, issuer CertificateIssuer, clock Clock, ids IDGenerator, random io.Reader, identityTTL time.Duration) (*IdentityService, error) {
	if store == nil || issuer == nil || clock == nil || ids == nil || random == nil {
		return nil, fmt.Errorf("collector identity dependencies are required")
	}
	if identityTTL < 5*time.Minute || identityTTL > 24*time.Hour {
		return nil, fmt.Errorf("collector identity lifetime must be between five minutes and 24 hours")
	}
	return &IdentityService{store: store, issuer: issuer, clock: clock, ids: ids, random: random, identityTTL: identityTTL}, nil
}

type BootstrapKey struct {
	BootstrapKeyID string
	Token          string
	ExpiresAt      time.Time
}

func (s *IdentityService) CreateBootstrapKey(ctx context.Context, clusterID domain.ClusterID, validFor time.Duration) (BootstrapKey, error) {
	if clusterID == "" {
		return BootstrapKey{}, fmt.Errorf("cluster identifier is required")
	}
	if validFor < time.Minute || validFor > 24*time.Hour {
		return BootstrapKey{}, fmt.Errorf("bootstrap lifetime must be between one minute and 24 hours")
	}
	keyID, err := s.ids.NewID()
	if err != nil {
		return BootstrapKey{}, fmt.Errorf("create bootstrap key identifier: %w", err)
	}
	rawToken := make([]byte, 32)
	if _, err := io.ReadFull(s.random, rawToken); err != nil {
		return BootstrapKey{}, fmt.Errorf("create bootstrap key secret: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(rawToken)
	tokenHash := sha256.Sum256([]byte(token))
	expiresAt := s.clock.Now().UTC().Add(validFor)
	if err := s.store.CreateBootstrapKey(ctx, keyID, clusterID, tokenHash, expiresAt); err != nil {
		return BootstrapKey{}, fmt.Errorf("persist bootstrap key: %w", err)
	}
	return BootstrapKey{BootstrapKeyID: keyID, Token: token, ExpiresAt: expiresAt}, nil
}

type EnrollmentRequest struct {
	BootstrapToken string
	CSRPEM         []byte
	Metadata       CollectorMetadata
}

type Enrollment struct {
	CollectorID domain.CollectorID
	Identity    IssuedIdentity
}

func (s *IdentityService) Enroll(ctx context.Context, request EnrollmentRequest) (Enrollment, error) {
	if request.BootstrapToken == "" || len(request.CSRPEM) == 0 {
		return Enrollment{}, fmt.Errorf("bootstrap token and certificate request are required")
	}
	if err := validateMetadata(request.Metadata); err != nil {
		return Enrollment{}, err
	}
	tokenHash := sha256.Sum256([]byte(request.BootstrapToken))
	grant, err := s.store.FindBootstrapGrant(ctx, tokenHash)
	if err != nil {
		return Enrollment{}, err
	}
	collectorIDValue, err := s.ids.NewID()
	if err != nil {
		return Enrollment{}, fmt.Errorf("create collector identifier: %w", err)
	}
	collectorID := domain.CollectorID(collectorIDValue)
	identity, err := s.issuer.Issue(grant.ClusterID, collectorID, request.CSRPEM, s.clock.Now().UTC(), s.identityTTL)
	if err != nil {
		return Enrollment{}, fmt.Errorf("issue collector identity: %w", err)
	}
	if err := s.store.ConsumeBootstrapAndEnroll(ctx, grant, tokenHash, collectorID, request.Metadata, identity); err != nil {
		return Enrollment{}, err
	}
	return Enrollment{CollectorID: collectorID, Identity: identity}, nil
}

func (s *IdentityService) Renew(ctx context.Context, collectorID domain.CollectorID, csrPEM []byte) (IssuedIdentity, error) {
	if collectorID == "" || len(csrPEM) == 0 {
		return IssuedIdentity{}, fmt.Errorf("collector identifier and certificate request are required")
	}
	clusterID, err := s.store.ActiveCollectorCluster(ctx, collectorID)
	if err != nil {
		return IssuedIdentity{}, err
	}
	identity, err := s.issuer.Issue(clusterID, collectorID, csrPEM, s.clock.Now().UTC(), s.identityTTL)
	if err != nil {
		return IssuedIdentity{}, fmt.Errorf("issue renewed collector identity: %w", err)
	}
	if err := s.store.RecordRenewedIdentity(ctx, collectorID, identity); err != nil {
		return IssuedIdentity{}, err
	}
	return identity, nil
}

func (s *IdentityService) Revoke(ctx context.Context, collectorID domain.CollectorID) error {
	if collectorID == "" {
		return fmt.Errorf("collector identifier is required")
	}
	return s.store.RevokeCollector(ctx, collectorID)
}

func validateMetadata(metadata CollectorMetadata) error {
	if metadata.DisplayName == "" || metadata.Version == "" || metadata.OperatingSystem == "" || metadata.Architecture == "" {
		return fmt.Errorf("collector display name, version, operating system, and architecture are required")
	}
	if metadata.ProtocolMin < 1 || metadata.ProtocolMax < metadata.ProtocolMin {
		return fmt.Errorf("collector protocol range is invalid")
	}
	return nil
}
