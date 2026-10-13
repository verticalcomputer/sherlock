package commandpack

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

var (
	ErrInvalidRelease = errors.New("invalid command-pack release")
	ErrUnknownRoot    = errors.New("unknown command-pack trust root")
	ErrInactiveRoot   = errors.New("inactive command-pack trust root")
	ErrBadSignature   = errors.New("invalid command-pack signature")
	ErrIncompatible   = errors.New("incompatible command-pack runner version")
)

func CanonicalBytes(pack Pack) ([]byte, error) {
	if err := ValidatePack(pack); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRelease, err)
	}
	encoded, err := json.Marshal(pack)
	if err != nil {
		return nil, fmt.Errorf("encode command pack: %w", err)
	}
	return encoded, nil
}

func Sign(pack Pack, trustRootID string, privateKey ed25519.PrivateKey) (SignedRelease, error) {
	if !validID(trustRootID) || len(privateKey) != ed25519.PrivateKeySize {
		return SignedRelease{}, fmt.Errorf("%w: signing identity or private key is invalid", ErrInvalidRelease)
	}
	payload, err := CanonicalBytes(pack)
	if err != nil {
		return SignedRelease{}, err
	}
	return SignedRelease{SchemaVersion: SchemaVersion, TrustRootID: trustRootID, Pack: pack, Signature: ed25519.Sign(privateKey, payload)}, nil
}

func EncodeRelease(release SignedRelease) ([]byte, error) {
	if release.SchemaVersion != SchemaVersion || !validID(release.TrustRootID) || len(release.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: signed envelope is invalid", ErrInvalidRelease)
	}
	if _, err := CanonicalBytes(release.Pack); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(release)
	if err != nil {
		return nil, fmt.Errorf("encode signed command pack: %w", err)
	}
	return encoded, nil
}

func DecodeRelease(encoded []byte) (SignedRelease, error) {
	var release SignedRelease
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&release); err != nil {
		return SignedRelease{}, fmt.Errorf("%w: decode: %v", ErrInvalidRelease, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return SignedRelease{}, fmt.Errorf("%w: trailing data", ErrInvalidRelease)
	}
	canonical, err := EncodeRelease(release)
	if err != nil {
		return SignedRelease{}, err
	}
	if !bytes.Equal(encoded, canonical) {
		return SignedRelease{}, fmt.Errorf("%w: release is not canonically encoded", ErrInvalidRelease)
	}
	return release, nil
}

type TrustStore struct{ roots map[string]TrustRoot }

func NewTrustStore(roots []TrustRoot) (*TrustStore, error) {
	if len(roots) == 0 {
		return nil, fmt.Errorf("trust store requires a root")
	}
	store := &TrustStore{roots: make(map[string]TrustRoot, len(roots))}
	for _, root := range roots {
		if !validID(root.ID) || !validID(root.Issuer) || len(root.PublicKey) != ed25519.PublicKeySize || !canonicalTime(root.ActivatesAt) || !canonicalTime(root.RetiresAt) || !root.RetiresAt.After(root.ActivatesAt) {
			return nil, fmt.Errorf("trust root %q is invalid", root.ID)
		}
		if _, exists := store.roots[root.ID]; exists {
			return nil, fmt.Errorf("duplicate trust root %q", root.ID)
		}
		root.PublicKey = bytes.Clone(root.PublicKey)
		store.roots[root.ID] = root
	}
	return store, nil
}

func (store *TrustStore) Verify(release SignedRelease, runnerVersion string, now time.Time) (*Catalog, error) {
	if store == nil || release.SchemaVersion != SchemaVersion || !validVersion(runnerVersion) || !canonicalTime(now) {
		return nil, fmt.Errorf("%w: verification inputs are invalid", ErrInvalidRelease)
	}
	root, exists := store.roots[release.TrustRootID]
	if !exists {
		return nil, ErrUnknownRoot
	}
	if now.Before(root.ActivatesAt) || !now.Before(root.RetiresAt) || release.Pack.IssuedAt.Before(root.ActivatesAt) || !release.Pack.IssuedAt.Before(root.RetiresAt) {
		return nil, ErrInactiveRoot
	}
	if release.Pack.Issuer != root.Issuer {
		return nil, fmt.Errorf("%w: issuer does not match trust root", ErrInvalidRelease)
	}
	if now.Before(release.Pack.IssuedAt) || !now.Before(release.Pack.ExpiresAt) {
		return nil, fmt.Errorf("%w: release is not currently valid", ErrInvalidRelease)
	}
	payload, err := CanonicalBytes(release.Pack)
	if err != nil {
		return nil, err
	}
	if len(release.Signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(root.PublicKey), payload, release.Signature) {
		return nil, ErrBadSignature
	}
	if compareVersion(runnerVersion, release.Pack.MinimumRunner) < 0 || compareVersion(runnerVersion, release.Pack.MaximumRunner) > 0 {
		return nil, ErrIncompatible
	}
	validNotBefore := release.Pack.IssuedAt
	if root.ActivatesAt.After(validNotBefore) {
		validNotBefore = root.ActivatesAt
	}
	validBefore := release.Pack.ExpiresAt
	if root.RetiresAt.Before(validBefore) {
		validBefore = root.RetiresAt
	}
	return newCatalog(release.Pack, validNotBefore, validBefore), nil
}
