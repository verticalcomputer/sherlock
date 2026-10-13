package nodeidentity

import (
	"crypto/rand"
	"encoding/base64"
)

// NewBootstrapToken returns a 256-bit bearer secret for protected local delivery
// and its domain-separated storage digest. Never echo the token in logs/status.
func NewBootstrapToken() (string, string, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", "", ErrUnavailable
	}
	token := base64.RawURLEncoding.EncodeToString(secret[:])
	hash, _ := BootstrapTokenHash(token)
	return token, hash, nil
}

func BootstrapTokenHash(token string) (string, error) {
	if len(token) != 43 {
		return "", ErrInvalid
	}
	secret, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != token {
		return "", ErrInvalid
	}
	return digest(append([]byte("sherlock.node-identity.bootstrap.v1\x00"), secret...)), nil
}
