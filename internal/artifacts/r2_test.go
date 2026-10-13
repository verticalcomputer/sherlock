package artifacts

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type memoryR2Client struct {
	mu      sync.Mutex
	objects map[string][]byte
	getErr  error
}

func newMemoryR2Client() *memoryR2Client { return &memoryR2Client{objects: make(map[string][]byte)} }

func (client *memoryR2Client) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	key := aws.ToString(input.Key)
	if aws.ToString(input.IfNoneMatch) == "*" {
		if _, exists := client.objects[key]; exists {
			return nil, &smithy.GenericAPIError{Code: "PreconditionFailed", Message: "exists"}
		}
	}
	payload, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, err
	}
	client.objects[key] = append([]byte(nil), payload...)
	return &s3.PutObjectOutput{}, nil
}

func (client *memoryR2Client) GetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.getErr != nil {
		return nil, client.getErr
	}
	payload, exists := client.objects[aws.ToString(input.Key)]
	if !exists {
		return nil, &smithy.GenericAPIError{Code: "NoSuchKey", Message: "missing"}
	}
	copy := append([]byte(nil), payload...)
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(copy)), ContentLength: aws.Int64(int64(len(copy)))}, nil
}

func (client *memoryR2Client) DeleteObject(_ context.Context, input *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	delete(client.objects, aws.ToString(input.Key))
	return &s3.DeleteObjectOutput{}, nil
}

func TestR2StoreStagesPromotesReadsAndReplaysContentAddressedArtifact(t *testing.T) {
	client := newMemoryR2Client()
	store, err := newR2Store(client, "audit", "sherlock/model-audit", 1024)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("redacted model payload")
	reference := testArtifactReference(t, payload)
	staged, err := store.Stage(context.Background(), "ev-1", reference, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Promote(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	read, err := store.Read(context.Background(), reference)
	if err != nil || !bytes.Equal(read, payload) {
		t.Fatalf("read=%q err=%v", read, err)
	}
	if _, exists := client.objects[store.stageKey(string(staged.ID))]; exists {
		t.Fatal("staging object remains after promotion")
	}

	replay, err := store.Stage(context.Background(), "ev-1", reference, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Promote(context.Background(), replay); err != nil {
		t.Fatalf("idempotent promotion: %v", err)
	}
	if got := client.objects[store.objectKey(reference)]; !bytes.Equal(got, payload) {
		t.Fatalf("content-addressed object=%q", got)
	}
}

func TestR2StoreRejectsCollisionAndMapsReconciliationConditions(t *testing.T) {
	client := newMemoryR2Client()
	store, _ := newR2Store(client, "audit", "", 1024)
	payload := []byte("original")
	reference := testArtifactReference(t, payload)
	staged, err := store.Stage(context.Background(), "ev-1", reference, payload)
	if err != nil {
		t.Fatal(err)
	}
	client.objects[store.objectKey(reference)] = []byte("collision")
	if err := store.Promote(context.Background(), staged); !errors.Is(err, application.ErrArtifactConflict) {
		t.Fatalf("collision error=%v", err)
	}
	if condition, err := store.Check(context.Background(), reference); err != nil || condition != domain.ArtifactCorrupt {
		t.Fatalf("corrupt condition=%s err=%v", condition, err)
	}
	delete(client.objects, store.objectKey(reference))
	if condition, err := store.Check(context.Background(), reference); err != nil || condition != domain.ArtifactUnavailable {
		t.Fatalf("missing condition=%s err=%v", condition, err)
	}
	client.getErr = &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied"}
	if _, err := store.Check(context.Background(), reference); err == nil {
		t.Fatal("provider access failure was misclassified as object absence")
	}
}

func TestR2StoreRejectsBoundsChecksumAndUnsafeConfiguration(t *testing.T) {
	client := newMemoryR2Client()
	store, _ := newR2Store(client, "audit", "prefix", 4)
	payload := []byte("12345")
	if _, err := store.Stage(context.Background(), "ev-1", testArtifactReference(t, payload), payload); !errors.Is(err, application.ErrArtifactTooLarge) {
		t.Fatalf("oversized stage error=%v", err)
	}
	small := []byte("1234")
	if _, err := store.Stage(context.Background(), "ev-1", testArtifactReference(t, small), []byte("abcd")); !errors.Is(err, application.ErrArtifactChecksumMismatch) {
		t.Fatalf("checksum stage error=%v", err)
	}
	malicious := application.StagedArtifact{ID: "../../outside", EvidenceID: "ev-1", Reference: testArtifactReference(t, small)}
	if err := store.Promote(context.Background(), malicious); err == nil {
		t.Fatal("staging key escape was accepted")
	}
	for _, config := range []R2Config{
		{Endpoint: "http://example.test", Bucket: "bucket", AccessKeyID: "id", SecretAccessKey: "secret", MaxBytes: 1},
		{Endpoint: "https://example.test/path", Bucket: "bucket", AccessKeyID: "id", SecretAccessKey: "secret", MaxBytes: 1},
		{Endpoint: "https://example.test", Bucket: "bad/bucket", AccessKeyID: "id", SecretAccessKey: "secret", MaxBytes: 1},
		{Endpoint: "https://example.test", Bucket: "bucket", AccessKeyID: "id", SecretAccessKey: "secret", Prefix: "../escape", MaxBytes: 1},
	} {
		if err := validateR2Config(config); err == nil {
			t.Fatalf("unsafe R2 config accepted: endpoint=%q bucket=%q prefix=%q", config.Endpoint, config.Bucket, config.Prefix)
		}
	}
}

func TestR2StoreImportsVerifiedContentWithoutOverwrite(t *testing.T) {
	client := newMemoryR2Client()
	store, _ := newR2Store(client, "audit", "migration", 1024)
	payload := []byte("legacy local artifact")
	created, err := store.ImportContentAddressed(context.Background(), payload)
	if err != nil || !created {
		t.Fatalf("first import created=%t err=%v", created, err)
	}
	created, err = store.ImportContentAddressed(context.Background(), payload)
	if err != nil || created {
		t.Fatalf("replay import created=%t err=%v", created, err)
	}
	reference := testArtifactReference(t, payload)
	if got := client.objects[store.objectKey(reference)]; !bytes.Equal(got, payload) {
		t.Fatalf("imported object=%q", got)
	}
}

func TestR2StoreConcurrentPromotionKeepsOneVerifiedObject(t *testing.T) {
	client := newMemoryR2Client()
	store, _ := newR2Store(client, "audit", "race", 1024)
	payload := []byte("concurrent immutable artifact")
	reference := testArtifactReference(t, payload)
	const workers = 24
	errorsChannel := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			staged, err := store.Stage(context.Background(), "ev-race", reference, payload)
			if err == nil {
				err = store.Promote(context.Background(), staged)
			}
			errorsChannel <- err
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("concurrent promotion error=%v", err)
		}
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.objects) != 1 || !bytes.Equal(client.objects[store.objectKey(reference)], payload) {
		t.Fatalf("objects after concurrent promotion=%d", len(client.objects))
	}
}
