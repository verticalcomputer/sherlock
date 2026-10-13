package nodetelemetry

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
	"github.com/verticalcomputer/sherlock/internal/telemetryjournal"
)

// This peer models immutable receipts, not gateway/cloud persistence. Every
// local ownership transition below exercises the actual durable node journal.
type retirementPeer struct {
	*fakeGateway
	controlMu                   sync.Mutex
	capabilities                telemetry.RetirementCapabilities
	capabilityError             error
	capabilityCalls             int
	releases                    map[string]telemetry.ReleaseEnvelope
	finals                      map[string]telemetry.GatewayRetirementReceipt
	completions                 map[string]telemetry.NodeReleaseCompletion
	completionReceipts          map[string]telemetry.NodeCompletionReceipt
	loseRelease, loseCompletion bool
	badFinal, badCompletion     bool
	capabilityEntered           chan struct{}
	capabilityBlocked           bool
}

func retirementFixture(t *testing.T) (Config, *retirementPeer, *time.Time, *string) {
	c, old, at, boot := fixture(t)
	peer := &retirementPeer{fakeGateway: old, capabilities: telemetry.SupportedRetirementCapabilities(), releases: map[string]telemetry.ReleaseEnvelope{}, finals: map[string]telemetry.GatewayRetirementReceipt{}, completions: map[string]telemetry.NodeReleaseCompletion{}, completionReceipts: map[string]telemetry.NodeCompletionReceipt{}}
	c.Gateway = peer
	return c, peer, at, boot
}
func (g *retirementPeer) RetirementCapabilities(ctx context.Context) (telemetry.RetirementCapabilities, error) {
	g.controlMu.Lock()
	g.capabilityCalls++
	blocked, entered, caps, err := g.capabilityBlocked, g.capabilityEntered, g.capabilities, g.capabilityError
	g.controlMu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if blocked {
		<-ctx.Done()
		return telemetry.RetirementCapabilities{}, ctx.Err()
	}
	return caps, err
}
func (g *retirementPeer) ReleaseOwnership(_ context.Context, e telemetry.ReleaseEnvelope) (telemetry.GatewayRetirementReceipt, error) {
	g.controlMu.Lock()
	defer g.controlMu.Unlock()
	if telemetry.ValidateReleaseEnvelope(e) != nil {
		return telemetry.GatewayRetirementReceipt{}, telemetry.ErrInvalid
	}
	if old, exists := g.releases[e.Request.ReleaseID]; exists && !reflect.DeepEqual(old, e) {
		return telemetry.GatewayRetirementReceipt{}, telemetry.ErrConflict
	}
	if _, exists := g.releases[e.Request.ReleaseID]; !exists {
		g.fakeGateway.mu.Lock()
		for _, fact := range e.Manifest.Batches {
			key := telemetry.BatchKey{ClusterID: e.Request.ClusterID, NodeID: e.Request.NodeID, EnrollmentID: e.Request.EnrollmentID, SessionEpoch: e.Request.SessionEpoch, SessionID: e.Request.SessionID, Sequence: fact.Sequence}
			ack, exists := g.batches[key]
			if !exists || ack.ID != fact.GatewayReceiptID || ack.Digest != fact.Digest {
				g.fakeGateway.mu.Unlock()
				return telemetry.GatewayRetirementReceipt{}, telemetry.ErrConflict
			}
		}
		g.fakeGateway.mu.Unlock()
		g.releases[e.Request.ReleaseID] = e
		final := telemetry.CloudRetirementReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: "cloud-final-" + e.Request.ReleaseID, Phase: "FINAL", Binding: e.Request.Binding(), GatewayAdmissionID: "admission-" + e.Request.ReleaseID, PreparedReceiptID: "prepared-" + e.Request.ReleaseID, GatewayCommitID: "commit-" + e.Request.ReleaseID, StoredAt: e.Request.CreatedAt, Durability: "CLOUD"}
		id, err := telemetry.GatewayRetirementReceiptID(final)
		if err != nil {
			return telemetry.GatewayRetirementReceipt{}, err
		}
		g.finals[e.Request.ReleaseID] = telemetry.GatewayRetirementReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: id, Binding: e.Request.Binding(), GatewayAdmissionID: final.GatewayAdmissionID, PreparedReceiptID: final.PreparedReceiptID, GatewayCommitID: final.GatewayCommitID, CloudFinalReceipt: final, StoredAt: final.StoredAt, Durability: "GATEWAY"}
	}
	if g.loseRelease {
		g.loseRelease = false
		return telemetry.GatewayRetirementReceipt{}, telemetry.ErrUnavailable
	}
	r := g.finals[e.Request.ReleaseID]
	if g.badFinal {
		r.Binding.ManifestDigest = string(make([]byte, 64))
	}
	return r, nil
}
func (g *retirementPeer) CompleteNodeRelease(_ context.Context, c telemetry.NodeReleaseCompletion) (telemetry.NodeCompletionReceipt, error) {
	g.controlMu.Lock()
	defer g.controlMu.Unlock()
	if old, exists := g.completions[c.ID]; exists && old != c {
		return telemetry.NodeCompletionReceipt{}, telemetry.ErrConflict
	}
	final, exists := g.finals[c.Binding.ReleaseID]
	if !exists || c.Binding != final.Binding || c.GatewayRetirementReceiptID != final.ID || c.CloudFinalReceiptID != final.CloudFinalReceipt.ID {
		return telemetry.NodeCompletionReceipt{}, telemetry.ErrConflict
	}
	g.completions[c.ID] = c
	if _, exists := g.completionReceipts[c.ID]; !exists {
		g.completionReceipts[c.ID] = telemetry.NodeCompletionReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: "cloud-completion-" + c.ID, Binding: c.Binding, CompletionDigest: c.Digest, CloudFinalReceiptID: c.CloudFinalReceiptID, GatewayRetirementReceiptID: c.GatewayRetirementReceiptID, StoredAt: c.CreatedAt, Durability: "CLOUD"}
	}
	if g.loseCompletion {
		g.loseCompletion = false
		return telemetry.NodeCompletionReceipt{}, telemetry.ErrUnavailable
	}
	r := g.completionReceipts[c.ID]
	if g.badCompletion {
		r.CompletionDigest = string(make([]byte, 64))
	}
	return r, nil
}
func retireStep(t *testing.T, r *Runtime) bool {
	t.Helper()
	progress, err := r.RetireOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return progress
}
func retireAll(t *testing.T, r *Runtime) {
	t.Helper()
	for turn := 0; turn < 64; turn++ {
		if !retireStep(t, r) {
			return
		}
	}
	t.Fatal("retirement bounded work did not finish")
}

func TestRetirementCapabilitiesCannotAuthorizeUnsupportedPeerPruning(t *testing.T) {
	c, _, _, _ := fixture(t)
	r := openRuntime(t, c)
	collect(t, r)
	drain(t, r)
	if progress, err := r.RetireOnce(context.Background()); err != nil || progress {
		t.Fatal(progress, err)
	}
	if pending, more, err := r.q.PendingReleases(context.Background(), "", 8); err != nil || more || len(pending) != 0 {
		t.Fatal(pending, more, err)
	}
	_ = r.Close()
	c2, peer, _, _ := retirementFixture(t)
	peer.capabilities.ReleaseVersion = 99
	r = openRuntime(t, c2)
	collect(t, r)
	drain(t, r)
	if _, err := r.RetireOnce(context.Background()); !errors.Is(err, telemetry.ErrBackpressure) {
		t.Fatal(err)
	}
	peer.capabilityError = telemetry.ErrInvalid
	if _, err := r.RetireOnce(context.Background()); !errors.Is(err, telemetry.ErrBackpressure) {
		t.Fatal(err)
	}
	if pending, _, _ := r.q.PendingReleases(context.Background(), "", 8); len(pending) != 0 {
		t.Fatal("unsupported peer sealed ownership")
	}
	collect(t, r)
	drain(t, r)
	if r.state.Sessions[0].LastAllocated != "2" || len(peer.batches) != 2 {
		t.Fatal("unsupported retirement interrupted collection")
	}
}

func TestActiveSessionReleaseContinuesExactSequenceAfterLostResponses(t *testing.T) {
	c, peer, at, _ := retirementFixture(t)
	r := openRuntime(t, c)
	collect(t, r)
	drain(t, r)
	retireStep(t, r) // authenticated capabilities
	peer.loseRelease = true
	if _, err := r.RetireOnce(context.Background()); !errors.Is(err, telemetry.ErrUnavailable) {
		t.Fatal(err)
	}
	pending, _, err := r.q.PendingReleases(context.Background(), "", 8)
	if err != nil || len(pending) != 1 || pending[0].Phase != "SEALED" {
		t.Fatal(pending, err)
	}
	original := telemetry.ReleaseEnvelope{Request: pending[0].Request, Manifest: pending[0].Manifest}
	_ = r.Close()
	*at = at.Add(time.Second)
	r = openRuntime(t, c)
	retireStep(t, r)
	retireStep(t, r)
	if r.state.Sessions[0].ReleasedThrough != "1" || r.state.Sessions[0].LastAllocated != "1" {
		t.Fatal("active allocation changed")
	}
	peer.loseCompletion = true
	if _, err = r.RetireOnce(context.Background()); !errors.Is(err, telemetry.ErrUnavailable) {
		t.Fatal(err)
	}
	pending, _, _ = r.q.PendingReleases(context.Background(), "", 8)
	if len(pending) != 1 || pending[0].Completion == nil {
		t.Fatal("completion not durably sealed")
	}
	completion := *pending[0].Completion
	_ = r.Close()
	r = openRuntime(t, c)
	retireStep(t, r)
	retireAll(t, r)
	if len(peer.releases) != 1 || !reflect.DeepEqual(peer.releases[original.Request.ReleaseID], original) || peer.completions[completion.ID] != completion {
		t.Fatal("immutable retry changed")
	}
	collect(t, r)
	drain(t, r)
	retireAll(t, r)
	if len(r.state.Sessions) != 1 || r.state.Sessions[0].Open.SessionEpoch != "1" || r.state.Sessions[0].LastAllocated != "2" || r.state.Sessions[0].ReleasedThrough != "2" {
		t.Fatal("active session reset")
	}
	for _, request := range peer.releases {
		if request.Request.ThroughSequence == "2" && request.Request.FromSequence != "2" {
			t.Fatal("released prefix reused")
		}
	}
}

func TestRetirementAllocatorCrashPreservesPendingProofBeforeCompletion(t *testing.T) {
	for _, point := range []string{"release_sealed", "release_allocator_compacted", "completion_sealed", "completion_ack_committed"} {
		t.Run(point, func(t *testing.T) {
			c, peer, _, _ := retirementFixture(t)
			r := openRuntime(t, c)
			collect(t, r)
			drain(t, r)
			retireStep(t, r)
			c.fault = func(got string) error {
				if got == point {
					return errors.New("synthetic interruption")
				}
				return nil
			}
			r.config.fault = c.fault
			failed := false
			for turn := 0; turn < 8; turn++ {
				if _, err := r.RetireOnce(context.Background()); err != nil {
					if !errors.Is(err, ErrState) {
						t.Fatal(err)
					}
					failed = true
					break
				}
			}
			if !failed {
				t.Fatal("fault point not exercised")
			}
			if point == "release_allocator_compacted" && len(peer.completions) != 0 {
				t.Fatal("completion preceded durable journal compaction")
			}
			_ = r.Close()
			c.fault = nil
			r = openRuntime(t, c)
			retireAll(t, r)
			if pending, _, err := r.q.PendingReleases(context.Background(), "", 8); err != nil || len(pending) != 0 {
				t.Fatal("pending lost or unresolved", pending, err)
			}
			if len(peer.releases) != 1 || len(peer.completions) != 1 || r.state.Sessions[0].ReleasedThrough != "1" {
				t.Fatal("retry duplicated proof")
			}
		})
	}
}

func TestBadFinalOrCompletionReceiptCannotReleaseOrClearPending(t *testing.T) {
	c, peer, _, _ := retirementFixture(t)
	r := openRuntime(t, c)
	collect(t, r)
	drain(t, r)
	retireStep(t, r)
	peer.badFinal = true
	if _, err := r.RetireOnce(context.Background()); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	if r.state.Sessions[0].ReleasedThrough != "0" {
		t.Fatal("malformed final compacted allocator")
	}
	peer.badFinal = false
	retireStep(t, r)
	peer.badCompletion = true
	if _, err := r.RetireOnce(context.Background()); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	if pending, _, _ := r.q.PendingReleases(context.Background(), "", 8); len(pending) != 1 || pending[0].Completion == nil {
		t.Fatal("malformed ack cleared completion")
	}
	peer.badCompletion = false
	retireAll(t, r)
}

func TestEmptyFinalizedSessionAndEpochBaseSurviveCompactionCrash(t *testing.T) {
	c, peer, at, boot := retirementFixture(t)
	r := openRuntime(t, c)
	drain(t, r)
	_ = r.Close()
	*boot = "boot-b"
	*at = at.Add(time.Minute)
	r = openRuntime(t, c)
	drain(t, r)
	retireStep(t, r)
	r.config.fault = func(point string) error {
		if point == "sessions_allocator_compacted" {
			return errors.New("synthetic interruption")
		}
		return nil
	}
	failed := false
	for turn := 0; turn < 8; turn++ {
		if _, err := r.RetireOnce(context.Background()); err != nil {
			failed = true
			break
		}
	}
	if !failed || r.state.BaseEpoch != 1 {
		t.Fatal("compaction callback not exercised")
	}
	_ = r.Close()
	r = openRuntime(t, c)
	retireAll(t, r)
	collect(t, r)
	drain(t, r)
	if r.state.BaseEpoch != 1 || len(r.state.Sessions) != 1 || r.state.Sessions[0].Open.SessionEpoch != "2" || r.state.Sessions[0].LastAllocated != "1" {
		t.Fatal("epoch/sequence reused")
	}
	for _, release := range peer.releases {
		if release.Request.SessionEpoch == "1" && (release.Request.FromSequence != "0" || release.Request.ThroughSequence != "0" || len(release.Manifest.Batches) != 0 || len(release.Manifest.Loss) != 0) {
			t.Fatal("empty release manufactured evidence")
		}
	}
}

func TestEightSessionsCanStartNinthOnlyAfterCompletedRetirement(t *testing.T) {
	c, _, at, boot := retirementFixture(t)
	for epoch := 1; epoch <= 8; epoch++ {
		*boot = "boot-" + strconv.Itoa(epoch)
		*at = at.Add(time.Minute)
		r := openRuntime(t, c)
		_ = r.Close()
	}
	*boot = "boot-9"
	*at = at.Add(time.Minute)
	r := openRuntime(t, c)
	if len(r.state.Sessions) != 8 || r.state.Sessions[7].Final == nil {
		t.Fatal("capacity replaced existing sessions")
	}
	if err := r.CollectOnce(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	drain(t, r)
	retireAll(t, r)
	collect(t, r)
	drain(t, r)
	if r.state.BaseEpoch != 8 || len(r.state.Sessions) != 1 || r.state.Sessions[0].Open.SessionEpoch != "9" {
		t.Fatal("historical epoch high-water lost")
	}
}

func TestGapReleaseUsesExactTransferredCarrierAndPreservesUnknownFields(t *testing.T) {
	c, peer, _, _ := retirementFixture(t)
	c.fault = func(point string) error {
		if point == "allocation_committed" {
			return errors.New("synthetic interruption")
		}
		return nil
	}
	r := openRuntime(t, c)
	if err := r.CollectOnce(context.Background()); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	_ = r.Close()
	c.fault = nil
	r = openRuntime(t, c)
	drain(t, r)
	retireStep(t, r)
	if retireStep(t, r) {
		t.Fatal("unknown gap retired before delivery")
	}
	collect(t, r)
	drain(t, r)
	loss := telemetry.SessionLoss{SourceID: c.Scope.SourceIDs[0], Range: gapRange(r.state.Gaps[0], c.Scope.SourceIDs[0])}
	digest, err := telemetry.CanonicalLossDigest(loss)
	if err != nil {
		t.Fatal(err)
	}
	retireAll(t, r)
	if len(r.state.Gaps) != 0 {
		t.Fatal("proven gap not compacted")
	}
	for _, release := range peer.releases {
		if len(release.Manifest.Loss) != 1 || release.Manifest.Loss[0].Digest != hex.EncodeToString(digest[:]) || release.Request.ThroughSequence != "2" {
			t.Fatal("gap proof changed", release)
		}
	}
	if loss.Range.CountKnown || loss.Range.FromAt != nil || loss.Range.ThroughAt != nil {
		t.Fatal("manufactured source facts")
	}
}

func TestFinalizedGapRequiresExactLifecycleHandoffBeforeRetirement(t *testing.T) {
	c, peer, at, boot := retirementFixture(t)
	c.fault = func(point string) error {
		if point == "allocation_committed" {
			return errors.New("synthetic interruption")
		}
		return nil
	}
	r := openRuntime(t, c)
	if err := r.CollectOnce(context.Background()); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	_ = r.Close()
	c.fault = nil
	*boot = "boot-b"
	*at = at.Add(time.Minute)
	r = openRuntime(t, c)
	final := r.state.Sessions[0].Final
	if final == nil || final.LastAllocatedSequence != "1" || len(final.Loss) != 1 || final.Loss[0].Range.CountKnown || final.Loss[0].Range.FromAt != nil || final.Loss[0].Range.ThroughAt != nil {
		t.Fatal("finalization manufactured or lost gap evidence")
	}
	retireStep(t, r) // capabilities cannot replace exact lifecycle delivery
	if retireStep(t, r) || len(peer.releases) != 0 {
		t.Fatal("undelivered finalization retired ownership")
	}
	drain(t, r)
	retireAll(t, r)
	if r.state.BaseEpoch != 1 || len(r.state.Gaps) != 0 || len(peer.batches) != 0 || len(peer.releases) != 1 {
		t.Fatal("final-only loss required a manufactured carrier or failed compaction")
	}
	for _, release := range peer.releases {
		if release.Request.FromSequence != "1" || release.Request.ThroughSequence != "1" || len(release.Manifest.Batches) != 0 || len(release.Manifest.Loss) != 1 {
			t.Fatal("final-only proof changed", release)
		}
	}
	collect(t, r)
	if r.state.Sessions[0].Open.SessionEpoch != "2" || r.state.Sessions[0].LastAllocated != "1" {
		t.Fatal("final-only retirement reused session allocation")
	}
}

func TestOldKeyCannotLeaveLocalConfigurationBeforeSessionCompaction(t *testing.T) {
	c, _, at, _ := retirementFixture(t)
	r := openRuntime(t, c)
	collect(t, r)
	drain(t, r)
	_ = r.Close()
	pubB, keyB, _ := ed25519.GenerateKey(rand.Reader)
	c.Scope.Keys[0].State = "VERIFY_ONLY"
	c.Scope.Keys = append(c.Scope.Keys, telemetry.NodeKey{ID: "key-b", Epoch: "2", PublicKeyBase64: base64.RawStdEncoding.EncodeToString(pubB), State: "ACTIVE"})
	c.SigningKeyID, c.SigningKey = "key-b", keyB
	*at = at.Add(time.Minute)
	r = openRuntime(t, c)
	drain(t, r)
	_ = r.Close()
	missingOld := c
	missingOld.Scope.Keys = append([]telemetry.NodeKey(nil), c.Scope.Keys[1:]...)
	if bad, err := Open(context.Background(), missingOld); !errors.Is(err, ErrState) {
		if bad != nil {
			_ = bad.Close()
		}
		t.Fatal("historical integrity archive replaced current ownership authority", err)
	}
	r = openRuntime(t, c)
	retireAll(t, r)
	if r.state.BaseEpoch != 1 {
		t.Fatal("failed configuration attempt altered ownership")
	}
}
func TestThirdLocalKeyAfterSessionRetirementUsesArchivedIntegrityOnly(t *testing.T) {
	c, _, at, _ := retirementFixture(t)
	r := openRuntime(t, c)
	collect(t, r)
	drain(t, r)
	_ = r.Close()
	pubB, keyB, _ := ed25519.GenerateKey(rand.Reader)
	c.Scope.Keys[0].State = "VERIFY_ONLY"
	c.Scope.Keys = append(c.Scope.Keys, telemetry.NodeKey{ID: "key-b", Epoch: "2", PublicKeyBase64: base64.RawStdEncoding.EncodeToString(pubB), State: "ACTIVE"})
	c.SigningKeyID = "key-b"
	c.SigningKey = keyB
	*at = at.Add(time.Minute)
	r = openRuntime(t, c)
	drain(t, r)
	retireAll(t, r)
	if r.state.BaseEpoch != 1 {
		t.Fatal("old key session not compacted")
	}
	_ = r.Close()
	pubC, keyC, _ := ed25519.GenerateKey(rand.Reader)
	c.Scope.Keys = []telemetry.NodeKey{c.Scope.Keys[1], {ID: "key-c", Epoch: "3", PublicKeyBase64: base64.RawStdEncoding.EncodeToString(pubC), State: "ACTIVE"}}
	c.Scope.Keys[0].State = "VERIFY_ONLY"
	c.SigningKeyID = "key-c"
	c.SigningKey = keyC
	*at = at.Add(time.Minute)
	r = openRuntime(t, c)
	if r.state.Sessions[len(r.state.Sessions)-1].Open.SessionEpoch != "3" {
		t.Fatal("third key reset epochs")
	}
	_ = r.Close()
	c.Scope.Keys[1].ID = "key-a"
	c.SigningKeyID = "key-a"
	if _, err := Open(context.Background(), c); !errors.Is(err, ErrState) {
		t.Fatal("historical key identity reused", err)
	}
}

func TestRetirementControlCancellationJoinsInFlightAndDoesNotBusyLoop(t *testing.T) {
	c, peer, _, _ := retirementFixture(t)
	peer.capabilityBlocked = true
	peer.capabilityEntered = make(chan struct{}, 1)
	r := openRuntime(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	select {
	case <-peer.capabilityEntered:
	// A concurrent first collection may defer the first control pass; its
	// documented idle retry is five seconds, so allow that bounded retry.
	case <-time.After(8 * time.Second):
		t.Fatal("control not scheduled")
	}
	if err := r.CollectOnce(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("control did not join")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	peer.controlMu.Lock()
	calls := peer.capabilityCalls
	peer.controlMu.Unlock()
	if calls != 1 {
		t.Fatal("busy control loop", calls)
	}
}

func TestReleaseAllocatorVersionIsExplicitAndOriginalSignedBatchUntouched(t *testing.T) {
	c, peer, _, _ := retirementFixture(t)
	r := openRuntime(t, c)
	collect(t, r)
	drain(t, r)
	original := []byte(nil)
	for _, wire := range peer.wires {
		original = append([]byte(nil), wire...)
	}
	retireAll(t, r)
	for _, wire := range peer.wires {
		if string(wire) != string(original) {
			t.Fatal("retirement rewrote signed telemetry")
		}
	}
	var old telemetry.NodeBatch
	if json.Unmarshal(original, &old) != nil {
		t.Fatal("original fixture invalid")
	}
	ownership, err := r.q.LookupOwnership(context.Background(), old.Key)
	if err != nil || ownership.Disposition != telemetryjournal.OwnershipTransferred && ownership.Disposition != telemetryjournal.OwnershipExpired {
		t.Fatal("retired original became absent", ownership, err)
	}
	body, err := json.Marshal(r.state)
	if err != nil {
		t.Fatal(err)
	}
	var persisted allocator
	if json.Unmarshal(body, &persisted) != nil || persisted.Version != 2 {
		t.Fatal("allocator schema not versioned")
	}
	_ = r.Close()
}

func TestLegacyAllocatorVersionFailsClosedWithoutRewritingEvidence(t *testing.T) {
	c, _, _, _ := retirementFixture(t)
	r := openRuntime(t, c)
	collect(t, r)
	s := clone(r.state)
	_ = r.Close()
	s.Version = 1
	s.Checksum = checksum(s)
	body, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.Root, allocatorName)
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if bad, err := Open(context.Background(), c); !errors.Is(err, ErrState) {
		if bad != nil {
			_ = bad.Close()
		}
		t.Fatal("legacy allocator silently migrated", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(body) {
		t.Fatal("unsupported allocator evidence modified", err)
	}
}

func TestPendingKnownTransferAfterCompactionNeverBecomesUnknownLoss(t *testing.T) {
	c, peer, _, _ := retirementFixture(t)
	r := openRuntime(t, c)
	collect(t, r)
	drain(t, r)
	var key telemetry.BatchKey
	for existing := range peer.batches {
		key = existing
	}
	retireAll(t, r)
	s := clone(r.state)
	s.Pending = &pendingAllocation{Key: key}
	if err := r.save(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	r = openRuntime(t, c)
	if r.state.Pending != nil || len(r.state.Gaps) != 0 || r.state.Sessions[0].LastAllocated != "1" {
		t.Fatal("known transfer manufactured loss or reused allocation")
	}
}
