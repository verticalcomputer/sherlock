package postgres

import (
	"context"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestNewRestrictedRemediationPoolRedactsInvalidConfiguration(t *testing.T) {
	pool, err := NewRestrictedRemediationPool(context.Background(), "%", domain.ClusterID("test-cluster"))
	if pool != nil || err == nil || err.Error() != "restricted remediation database configuration is invalid" {
		t.Fatalf("invalid restricted database configuration pool=%v err=%v", pool, err)
	}
}
