package investigationapi

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func newSnapshotReader(pool *pgxpool.Pool) (*storepg.InvestigationStore, error) {
	store, err := storepg.NewInvestigationStore(pool)
	if err != nil {
		return nil, fmt.Errorf("configure investigation snapshot reader: %w", err)
	}
	return store, nil
}
