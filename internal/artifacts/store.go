package artifacts

import (
	"context"
	"fmt"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	BackendLocal = "local"
	BackendR2    = "r2"
)

// Store is the complete artifact capability required across Sherlock's
// composition roots: transactional staging, verified reads, and reconciliation.
type Store interface {
	application.ArtifactStore
	application.ArtifactChecker
	Read(context.Context, domain.ArtifactReference) ([]byte, error)
}

type Options struct {
	Backend         string
	LocalRoot       string
	Endpoint        string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	Prefix          string
	MaxBytes        int64
}

func NewStore(ctx context.Context, options Options) (Store, error) {
	switch options.Backend {
	case BackendLocal:
		return NewLocalStore(options.LocalRoot, options.MaxBytes)
	case BackendR2:
		store, err := NewR2Store(ctx, R2Config{
			Endpoint: options.Endpoint, Bucket: options.Bucket,
			AccessKeyID: options.AccessKeyID, SecretAccessKey: options.SecretAccessKey,
			Prefix: options.Prefix, MaxBytes: options.MaxBytes,
		})
		if err != nil {
			return nil, err
		}
		return store, nil
	default:
		return nil, fmt.Errorf("artifact backend must be local or r2")
	}
}
