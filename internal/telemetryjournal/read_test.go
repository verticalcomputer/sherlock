package telemetryjournal

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDrainReachesFreshBeyondOldestPageAndReservesControl(t *testing.T) {
	o := testOptions(Node)
	clock := testAt
	o.Now = func() time.Time { return clock }
	q := mustOpen(t, filepath.Join(t.TempDir(), "queue"), o)
	for i := 1; i <= 150; i++ {
		clock = clock.Add(time.Second)
		mustPut(t, q, testBody(i, Data, "one"))
	}
	old, e := q.Next(ctx, 128)
	if e != nil || len(old) != 128 || old[127].Key.Sequence != "128" {
		t.Fatal("fixture head page", e)
	}
	fresh, ok, e := q.NextForDrain(ctx, 0)
	if e != nil || !ok || fresh.Key.Sequence != "150" {
		t.Fatal("fresh outside head page inaccessible", fresh, e)
	}
	backlog, ok, e := q.NextForDrain(ctx, 1)
	if e != nil || !ok || backlog.Key.Sequence != "1" {
		t.Fatal("oldest backlog starved", backlog, e)
	}
	clock = clock.Add(time.Second)
	mustPut(t, q, testBody(151, Contact, "contact"))
	control, ok, e := q.NextForDrain(ctx, 4)
	if e != nil || !ok || control.Key.Sequence != "151" {
		t.Fatal("reserved control turn missing", control, e)
	}
}
func TestLocalLossPaginationUsesDurableOrdinalForLateOldSequence(t *testing.T) {
	o := testOptions(Node)
	path := filepath.Join(t.TempDir(), "queue")
	q := mustOpen(t, path, o)
	for i := 1; i <= 3; i++ {
		mustPut(t, q, testBody(i, Data, "one"))
	}
	q.RecordLoss(ctx, testKey(3), "NODE_CAPACITY")
	first, cursor, more, e := q.LocalLosses(ctx, 0, 1)
	if e != nil || more || len(first) != 1 || first[0].Loss.AffectedKey.Sequence != "3" {
		t.Fatal(first, cursor, more, e)
	}
	q.RecordLoss(ctx, testKey(1), "NODE_EXPIRED")
	q.RecordLoss(ctx, testKey(2), "NODE_CAPACITY")
	q.Close()
	q = mustOpen(t, path, o)
	second, next, more, e := q.LocalLosses(ctx, cursor, 1)
	if e != nil || !more || len(second) != 1 || next <= cursor || second[0].Loss.AffectedKey.Sequence != "1" {
		t.Fatal("late old loss fell behind cursor", second, next, more, e)
	}
	last, _, more, e := q.LocalLosses(ctx, next, 1)
	if e != nil || more || len(last) != 1 || last[0].Loss.AffectedKey.Sequence != "2" {
		t.Fatal(last, more, e)
	}
	entry, e := q.Lookup(ctx, testKey(1))
	if e != nil || entry.Loss == nil || entry.Loss.Reason != "NODE_EXPIRED" || entry.Loss.Count != nil {
		t.Fatal("lookup lost exact disposition", entry, e)
	}
}
func TestSchema1JournalRejectedWithoutDatabaseMutation(t *testing.T) {
	o := testOptions(Node)
	path := filepath.Join(t.TempDir(), "queue")
	q := mustOpen(t, path, o)
	q.Close()
	metadata := filepath.Join(path, "metadata.sqlite")
	before, _ := os.ReadFile(metadata)
	marker := filepath.Join(path, "identity.json")
	data, _ := os.ReadFile(marker)
	var value map[string]any
	json.Unmarshal(data, &value)
	value["Version"] = 1
	old, _ := json.Marshal(value)
	os.WriteFile(marker, old, 0600)
	_, e := Open(path, o)
	assertError(t, e, ErrCorrupt)
	after, _ := os.ReadFile(metadata)
	if !bytes.Equal(before, after) {
		t.Fatal("unsupported schema journal mutated")
	}
}
func TestCompactReceiptsPreserveExactNanosecondInstants(t *testing.T) {
	o := testOptions(Node)
	o.Now = func() time.Time { return testAt.Add(987654321 * time.Nanosecond) }
	path := filepath.Join(t.TempDir(), "queue")
	q := mustOpen(t, path, o)
	r := mustPut(t, q, testBody(1, Data, "one"))
	ack := r
	ack.ID = "gateway-a"
	ack.Durability = "GATEWAY"
	ack.StoredAt = testAt.Add(123456789 * time.Nanosecond).In(time.FixedZone("same-instant", 19800))
	if e := q.Acknowledge(ctx, ack, ""); e != nil {
		t.Fatal(e)
	}
	q.Close()
	q = mustOpen(t, path, o)
	entry, e := q.Lookup(ctx, r.Key)
	if e != nil || entry.State != "TRANSFERRED" || !sameReceipt(entry.Receipt, r) {
		t.Fatal("compact receipt changed", entry, e)
	}
	if e = q.Acknowledge(ctx, ack, ""); e != nil {
		t.Fatal("same exact instant acknowledgement replay rejected", e)
	}
}

func TestDrainExcludesOldSessionBeforeLimitAndPreservesFairness(t *testing.T) {
	f := newSessionFixture()
	clock := testAt
	f.options.Now = func() time.Time { return clock }
	q := mustOpen(t, filepath.Join(t.TempDir(), "queue"), f.options)
	old := f.message(t, "OPEN", 1, "boot-old", "key-a", "")
	current := f.message(t, "OPEN", 2, "boot-new", "key-b", "")
	mustRegister(t, q, old)
	mustRegister(t, q, current)
	mustPut(t, q, sessionBody(old, "1"))
	clock = clock.Add(time.Second)
	mustPut(t, q, sessionBody(current, "1"))
	clock = clock.Add(time.Second)
	mustPut(t, q, sessionBody(current, "2"))
	for _, test := range []struct {
		turn     uint64
		sequence string
	}{{0, "2"}, {1, "1"}, {2, "1"}, {3, "1"}} {
		got, found, e := q.NextForDrainExcludingSessions(ctx, test.turn, []string{"1"})
		if e != nil || !found || got.Key.SessionEpoch != "2" || got.Key.Sequence != test.sequence {
			t.Fatal("exclusion changed weighted data selection", got, found, e)
		}
	}
	var contact Envelope
	if e := json.Unmarshal(sessionBody(current, "3"), &contact); e != nil {
		t.Fatal(e)
	}
	contact.Lane = Contact
	body, _ := json.Marshal(contact)
	clock = clock.Add(time.Second)
	mustPut(t, q, body)
	reserved, found, e := q.NextForDrainExcludingSessions(ctx, 4, []string{"1"})
	if e != nil || !found || reserved.Key.Sequence != "3" || reserved.Lane != Contact {
		t.Fatal("reserved control starved", reserved, e)
	}
	// The same exclusion is applied to fallback when no data lane exists.
	if _, found, e = q.NextForDrainExcludingSessions(ctx, 1, []string{"1", "2"}); e != nil || found {
		t.Fatal("excluded fallback returned owned data", found, e)
	}
	if _, e = q.Read(ctx, sessionBatch(old, "1").Key); e != nil {
		t.Fatal("temporary exclusion altered old owned bytes", e)
	}
	original, found, e := q.NextForDrain(ctx, 1)
	if e != nil || !found || original.Key.SessionEpoch != "1" {
		t.Fatal("empty exclusion no longer preserves original API", original, e)
	}
	for _, sequence := range []string{"1", "2"} {
		entry, e := q.Lookup(ctx, sessionBatch(current, sequence).Key)
		if e != nil {
			t.Fatal(e)
		}
		ack := entry.Receipt
		ack.ID = "cloud-" + sequence
		ack.Durability = "CLOUD"
		if e = q.Acknowledge(ctx, ack, entry.Receipt.ID); e != nil {
			t.Fatal(e)
		}
	}
	fallback, found, e := q.NextForDrainExcludingSessions(ctx, 1, []string{"1"})
	if e != nil || !found || fallback.Key.SessionEpoch != "2" || fallback.Key.Sequence != "3" {
		t.Fatal("excluded old data resurfaced through fallback", fallback, e)
	}
	for _, invalid := range [][]string{{"0"}, {"01"}, {"-1"}, {"*"}, {"1", "1"}, {"18446744073709551616"}, {"1", "2", "3", "4", "5", "6", "7", "8", "9"}} {
		_, _, e = q.NextForDrainExcludingSessions(ctx, 0, invalid)
		assertError(t, e, ErrInvalid)
	}
}
