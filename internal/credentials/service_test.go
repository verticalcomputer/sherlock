package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type testClock struct{ now time.Time }

func (clock *testClock) Now() time.Time { return clock.now }

type recordingAcceptor struct {
	mu    sync.Mutex
	value []byte
}

func testBinding() Binding {
	return Binding{RunID: "run-1", WorkID: "work-1", Attempt: 1, RunnerID: "runner-1", PlanDigest: domain.ChecksumSHA256([]byte("plan"))}
}

func (acceptor *recordingAcceptor) Accept(_ context.Context, _ Challenge, secret *Secret) error {
	return secret.Use(func(value []byte) error {
		acceptor.mu.Lock()
		defer acceptor.mu.Unlock()
		acceptor.value = append([]byte(nil), value...)
		return nil
	})
}

func TestChallengeIsEncryptedSingleUseAndDestroyed(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)}
	acceptor := &recordingAcceptor{}
	service, err := NewService(clock, strings.NewReader(strings.Repeat("r", 256)), acceptor)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	challenge, err := service.Create(domain.ClusterID("cluster-a"), testBinding(), "sudo diagnostic", []string{"comp001"}, []Field{FieldPassword}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	secretText := []byte(`{"password":"synthetic-secret"}`)
	submission, err := SealForChallenge(challenge, secretText)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%+v", submission), "synthetic-secret") {
		t.Fatal("submission exposed plaintext")
	}
	if err := service.Submit(context.Background(), challenge.ID, submission); err != nil {
		t.Fatal(err)
	}
	if string(acceptor.value) != string(secretText) {
		t.Fatalf("accepted value = %q", acceptor.value)
	}
	if err := service.Submit(context.Background(), challenge.ID, submission); !errors.Is(err, ErrUsed) {
		t.Fatalf("second use error = %v", err)
	}
	service.mu.Lock()
	entry := service.states[challenge.ID]
	service.mu.Unlock()
	if len(entry.private) != 0 {
		t.Fatal("private key retained after submission")
	}
}

func TestMalformedSubmissionFailsClosedAndConsumesChallenge(t *testing.T) {
	clock := &testClock{now: time.Now()}
	service, _ := NewService(clock, strings.NewReader(strings.Repeat("x", 256)), &recordingAcceptor{})
	defer service.Close()
	challenge, _ := service.Create("cluster-a", testBinding(), "diagnostic", []string{"comp001"}, []Field{FieldOTP}, time.Minute)
	if err := service.Submit(context.Background(), challenge.ID, Submission{Ciphertext: "not-base64"}); !errors.Is(err, ErrRejected) {
		t.Fatalf("error = %v", err)
	}
	if err := service.Submit(context.Background(), challenge.ID, Submission{}); !errors.Is(err, ErrUsed) {
		t.Fatalf("retry error = %v", err)
	}
}

func TestExpiredChallengeCannotBeUsedAndCleanupDestroysState(t *testing.T) {
	clock := &testClock{now: time.Now()}
	service, _ := NewService(clock, strings.NewReader(strings.Repeat("z", 256)), &recordingAcceptor{})
	defer service.Close()
	challenge, _ := service.Create("cluster-a", testBinding(), "diagnostic", []string{"comp001"}, []Field{FieldPassword}, time.Second)
	clock.now = clock.now.Add(2 * time.Second)
	if err := service.Submit(context.Background(), challenge.ID, Submission{}); !errors.Is(err, ErrExpired) {
		t.Fatalf("error = %v", err)
	}
	if removed := service.DestroyExpired(); removed != 1 {
		t.Fatalf("removed = %d", removed)
	}
	service.mu.Lock()
	_, retained := service.states[challenge.ID]
	service.mu.Unlock()
	if retained {
		t.Fatal("expired challenge retained")
	}
}

func TestSecretCannotBeFormattedOrMarshaled(t *testing.T) {
	secret := &Secret{bytes: []byte("do-not-print")}
	defer secret.Destroy()
	if got := fmt.Sprintf("%v %#v %+v", secret, secret, secret); strings.Contains(got, "do-not-print") || !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("formatted secret = %q", got)
	}
	if _, err := json.Marshal(secret); err == nil {
		t.Fatal("secret JSON marshaling succeeded")
	}
	if _, err := secret.MarshalText(); err == nil {
		t.Fatal("secret text marshaling succeeded")
	}
}

func TestCreateRejectsTargetExpansionAndUnknownFields(t *testing.T) {
	clock := &testClock{now: time.Now()}
	service, _ := NewService(clock, strings.NewReader(strings.Repeat("q", 512)), &recordingAcceptor{})
	defer service.Close()
	if _, err := service.Create("cluster-a", testBinding(), "diagnostic", []string{"comp001", "comp001"}, []Field{FieldPassword}, time.Minute); !errors.Is(err, ErrRejected) {
		t.Fatalf("duplicate target error = %v", err)
	}
	if _, err := service.Create("cluster-a", testBinding(), "diagnostic", []string{"comp001"}, []Field{"TOKEN"}, time.Minute); !errors.Is(err, ErrRejected) {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestReturnedChallengeCannotMutateStoredScope(t *testing.T) {
	clock := &testClock{now: time.Now()}
	acceptor := &recordingAcceptor{}
	service, _ := NewService(clock, strings.NewReader(strings.Repeat("m", 512)), acceptor)
	defer service.Close()
	challenge, err := service.Create("cluster-a", testBinding(), "diagnostic", []string{"comp001"}, []Field{FieldPassword}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	challenge.TargetIDs[0] = "attacker-target"
	challenge.Fields[0] = FieldOTP
	service.mu.Lock()
	stored := service.states[challenge.ID].challenge
	service.mu.Unlock()
	if stored.TargetIDs[0] != "comp001" || stored.Fields[0] != FieldPassword {
		t.Fatalf("stored challenge was mutated: %+v", stored)
	}
}

func TestSecretValueCannotBypassFormattingOrMarshaling(t *testing.T) {
	value := Secret{bytes: []byte("do-not-print")}
	defer value.Destroy()
	if got := fmt.Sprintf("%v %#v", value, value); strings.Contains(got, "100 111") || !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("formatted value secret = %q", got)
	}
	if _, err := json.Marshal(value); err == nil {
		t.Fatal("value secret JSON marshaling succeeded")
	}
}

func TestOversizedEncodedSubmissionIsRejectedBeforeDecode(t *testing.T) {
	clock := &testClock{now: time.Now()}
	service, _ := NewService(clock, strings.NewReader(strings.Repeat("b", 512)), &recordingAcceptor{})
	defer service.Close()
	challenge, _ := service.Create("cluster-a", testBinding(), "diagnostic", []string{"comp001"}, []Field{FieldPassword}, time.Minute)
	submission := Submission{ClientPublicKey: strings.Repeat("A", 1<<20), Nonce: strings.Repeat("A", 1<<20), Ciphertext: strings.Repeat("A", 1<<20)}
	if err := service.Submit(context.Background(), challenge.ID, submission); !errors.Is(err, ErrRejected) {
		t.Fatalf("oversized submission error = %v", err)
	}
}

func TestChallengeRequiresExactExecutionBinding(t *testing.T) {
	clock := &testClock{now: time.Now()}
	service, _ := NewService(clock, strings.NewReader(strings.Repeat("v", 512)), &recordingAcceptor{})
	defer service.Close()
	invalid := testBinding()
	invalid.PlanDigest = domain.SHA256{}
	if _, err := service.Create("cluster-a", invalid, "diagnostic", []string{"comp001"}, []Field{FieldPassword}, time.Minute); !errors.Is(err, ErrRejected) {
		t.Fatalf("unbound challenge error = %v", err)
	}
}
