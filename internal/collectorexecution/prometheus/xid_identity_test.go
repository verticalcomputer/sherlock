package prometheus

import (
	"testing"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestLegacyXIDRejectsConflictingAliasesAndPreservesIndices(t *testing.T) {
	task := domain.CollectionTask{Query: domain.QueryGPUXID}
	for _, labels := range []map[string]string{
		{"Hostname": "node-a", "hostname": "node-b", "UUID": "GPU-a"},
		{"Hostname": "node-a", "UUID": "GPU-a", "uuid": "GPU-b"},
	} {
		if _, err := entityKey(task, labels); err == nil {
			t.Fatal("conflicting XID identity accepted")
		}
	}
	for _, labels := range []map[string]string{
		{"Hostname": "node-a", "UUID": "GPU-a"},
		{"Hostname": "node-a", "hostname": "node-a", "UUID": "GPU-a", "uuid": "GPU-a"},
		{"hostname": "node-a", "gpu": "0"},
	} {
		if _, err := entityKey(task, labels); err != nil {
			t.Fatalf("compatible XID identity rejected: %v", err)
		}
	}
}
