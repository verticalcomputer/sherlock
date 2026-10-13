package telemetryjournal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

// This synthetic scale gate validates 60,480 compact receipts under the default
// 64MiB metadata cap, targeting <=32MiB with worst-length IDs and 16 sources.
// It measures sampled Go heap growth, not runtime RSS or a receipt expiry gate.
func TestRecoveryWeeklyReceiptLedgerBoundedMemory(t *testing.T) {
	if os.Getenv("SHERLOCK_TELEMETRY_WEEKLY") != "1" {
		t.Skip("explicit60480receipt synthetic resource gate")
	}
	o := testOptions(Gateway)
	o.Scope = Scope{strings.Repeat("c", 128), strings.Repeat("n", 128), strings.Repeat("e", 128)}
	o.SourceIDs = nil
	for i := 0; i < 16; i++ {
		o.SourceIDs = append(o.SourceIDs, strings.Repeat("s", 125)+fmt.Sprintf("%03d", i))
	}
	path := filepath.Join(t.TempDir(), "queue")
	q := mustOpen(t, path, o)
	tx, e := q.db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	statement, e := tx.Prepare(`INSERT INTO items(id,key,digest,wire,bytes,created,stored,lane,sources,state,receipt,ack,acked)VALUES(?,?,?,?,?,?,?,?,?,'TRANSFERRED',?,?,?)`)
	if e != nil {
		t.Fatal(e)
	}
	for i := 1; i <= 60480; i++ {
		key := telemetry.BatchKey{ClusterID: o.Scope.ClusterID, NodeID: o.Scope.NodeID, EnrollmentID: o.Scope.EnrollmentID, SessionEpoch: "1", SessionID: strings.Repeat("i", 128), Sequence: strconv.FormatUint(^uint64(0)-60480+uint64(i), 10)}
		id, keyJSON := keyID(key)
		digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		r := telemetry.Receipt{ProtocolVersion: 1, ID: strings.Repeat("r", 122) + fmt.Sprintf("%06d", i), Key: key, Digest: digest, StoredAt: testAt.Add(123456789 * time.Nanosecond), Durability: "GATEWAY"}
		rb, _ := json.Marshal(r)
		r.ID = strings.Repeat("a", 122) + fmt.Sprintf("%06d", i)
		r.Durability = "CLOUD"
		ab, _ := json.Marshal(r)
		if _, e = statement.Exec(id, keyJSON, digest, digest, 512, testAt.UnixNano(), testAt.UnixNano(), Data, mustJSON(o.SourceIDs), rb, ab, testAt.UnixNano()); e != nil {
			t.Fatal("synthetic ledger fixture insert", i, e)
		}
	}
	statement.Close()
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	q.Close()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var peak atomic.Uint64
	peak.Store(before.HeapAlloc)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				var stats runtime.MemStats
				runtime.ReadMemStats(&stats)
				for old := peak.Load(); stats.HeapAlloc > old; old = peak.Load() {
					if peak.CompareAndSwap(old, stats.HeapAlloc) {
						break
					}
				}
			}
		}
	}()
	started := time.Now()
	q, e = Open(path, o)
	close(stop)
	<-done
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	s, e := q.Stats(ctx)
	if e != nil || s.Transferred != 60480 {
		t.Fatal("weekly ledger failed validation", s, e)
	}
	growth := peak.Load() - before.HeapAlloc
	t.Logf("synthetic_receipts=60480 startup=%s physical_bytes=%d peak_go_heap_growth_bytes=%d", time.Since(started), s.PhysicalBytes, growth)
	if growth > 96<<20 {
		t.Fatal("bounded startup Go heap exceeded96MiB gate")
	}
	q.Close()
	if s.PhysicalBytes > 32<<20 {
		t.Fatal("worst128BIDs16sources weekly ledger exceeds32MiB target", s.PhysicalBytes)
	}
	q = mustOpen(t, path, o)
	q.Close()
}

func mustJSON(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return b
}
