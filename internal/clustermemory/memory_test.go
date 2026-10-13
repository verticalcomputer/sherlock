package clustermemory

import (
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestFactualMemoryRequiresCitation(t *testing.T) {
	now := time.Now().UTC()
	digest := domain.ChecksumSHA256([]byte("memory"))
	entry := Entry{ID: "memory-1", ClusterID: "cluster-a", Kind: KindValidatedFinding, Trust: TrustValidatedFinding, SourceInvestigationID: "inv-1", SourceFindingID: "finding-1", EntityKind: "node", EntityIDs: []string{"node-1"}, Statement: "GPU fault observed", Summary: "GPU fault observed", ValidFrom: now, CreatedAt: now, Completeness: "COMPLETE", Freshness: "CURRENT", RetentionClass: "investigation", ContentDigest: digest, IdempotencyKey: "finding/finding-1"}
	if err := entry.Validate(); err == nil {
		t.Fatal("uncited factual memory accepted")
	}
	entry.Citations = []Citation{{EvidenceID: "evidence-1", Relationship: "EVIDENCE"}}
	if err := entry.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryModeRejectsImplicitEnablement(t *testing.T) {
	if Mode("").Validate() == nil || Mode("TRUE").Validate() == nil {
		t.Fatal("ambiguous memory mode accepted")
	}
	for _, mode := range []Mode{ModeDisabled, ModeShadow, ModeEnabled} {
		if err := mode.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLexicalQueryIsBoundedAndOperatorSafe(t *testing.T) {
	query := tsQuery("Why is node-1 unhealthy? DROP:* | GPU/XID; --", []string{"node-1"})
	if query != "node | unhealthy | drop | gpu | xid" {
		t.Fatalf("query=%q", query)
	}
}
