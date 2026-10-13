package application

import (
	"context"
	"fmt"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// InventoryClass identifies whether a revision is the administrator-declared
// denominator or an observed source report.  The classes are deliberately not
// inferred from a source kind or collection outcome.
type InventoryClass string

const (
	InventoryExpected InventoryClass = "EXPECTED"
	InventoryObserved InventoryClass = "OBSERVED"
)

func (class InventoryClass) Validate() error {
	switch class {
	case InventoryExpected, InventoryObserved:
		return nil
	default:
		return fmt.Errorf("unknown inventory class %q", class)
	}
}

type InventoryRevisionProjection struct {
	Class    InventoryClass
	Revision domain.InventoryRevision
}

// GoodputStore is owned by the application consumers of the GP-02 contracts.
// It intentionally exposes expected and observed inventory through different
// methods, so a source report cannot replace an administrator's denominator.
type GoodputStore interface {
	RecordExpectedInventoryRevision(context.Context, domain.InventoryRevision) (bool, error)
	// RecordExpectedInventoryRevisionIfCurrentBefore atomically serializes an
	// approval with the expected-inventory fact stream. accepted is false when
	// a revision already in force was approved at or after previewGeneratedAt.
	RecordExpectedInventoryRevisionIfCurrentBefore(context.Context, domain.InventoryRevision, time.Time) (recorded, accepted bool, err error)
	RecordObservedInventoryRevision(context.Context, domain.InventoryRevision) (bool, error)
	RecordAllocationSnapshot(context.Context, domain.AllocationSnapshot) (bool, error)
	GetInventoryRevision(context.Context, domain.ClusterID, domain.InventoryRevisionID) (InventoryRevisionProjection, bool, error)
	GetCurrentInventoryRevision(context.Context, domain.ClusterID, domain.SourceID, InventoryClass) (InventoryRevisionProjection, bool, error)
	ListCurrentAllocationSnapshots(context.Context, domain.ClusterID, int) ([]domain.AllocationSnapshot, bool, error)
}

func ValidateGoodputLimit(limit int) error {
	if limit < 1 || limit > MaxPageSize {
		return fmt.Errorf("goodput page size must be in [1, %d]", MaxPageSize)
	}
	return nil
}
