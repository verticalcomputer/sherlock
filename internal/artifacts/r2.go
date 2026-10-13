package artifacts

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type R2Config struct {
	Endpoint        string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	Prefix          string
	MaxBytes        int64
}

type r2Client interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

type R2Store struct {
	client   r2Client
	bucket   string
	prefix   string
	maxBytes int64
}

func NewR2Store(ctx context.Context, config R2Config) (*R2Store, error) {
	if err := validateR2Config(config); err != nil {
		return nil, err
	}
	sdkConfig, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("auto"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(config.AccessKeyID, config.SecretAccessKey, "")),
		awsconfig.WithRetryMaxAttempts(3),
		// R2 does not implement x-amz-sdk-checksum-algorithm. Sherlock verifies
		// its own SHA-256 content address after every promotion and read.
		awsconfig.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired),
	)
	if err != nil {
		return nil, fmt.Errorf("configure R2 client: %w", err)
	}
	client := s3.NewFromConfig(sdkConfig, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(strings.TrimSuffix(config.Endpoint, "/"))
		options.UsePathStyle = true
	})
	return newR2Store(client, config.Bucket, config.Prefix, config.MaxBytes)
}

func newR2Store(client r2Client, bucket, prefix string, maxBytes int64) (*R2Store, error) {
	if client == nil {
		return nil, fmt.Errorf("R2 client is required")
	}
	if bucket == "" {
		return nil, fmt.Errorf("R2 bucket is required")
	}
	if maxBytes < 1 || maxBytes > 100<<20 {
		return nil, fmt.Errorf("artifact byte limit must be between 1 byte and 100 MiB")
	}
	return &R2Store{client: client, bucket: bucket, prefix: strings.Trim(prefix, "/"), maxBytes: maxBytes}, nil
}

func validateR2Config(config R2Config) error {
	if config.Endpoint == "" || config.Bucket == "" || config.AccessKeyID == "" || config.SecretAccessKey == "" {
		return fmt.Errorf("R2 endpoint, bucket, and credentials are required")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") {
		return fmt.Errorf("R2 endpoint must be an origin-only HTTPS URL")
	}
	if strings.ContainsAny(config.Bucket, "/\\\x00\r\n\t ") {
		return fmt.Errorf("R2 bucket is invalid")
	}
	prefix := strings.Trim(config.Prefix, "/")
	if prefix != "" && (path.Clean(prefix) != prefix || strings.ContainsAny(prefix, "\\\x00\r\n")) {
		return fmt.Errorf("R2 prefix must be a normalized relative object-key prefix")
	}
	for _, segment := range strings.Split(prefix, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("R2 prefix must be a normalized relative object-key prefix")
		}
	}
	if config.MaxBytes < 1 || config.MaxBytes > 100<<20 {
		return fmt.Errorf("artifact byte limit must be between 1 byte and 100 MiB")
	}
	return nil
}

func (store *R2Store) Stage(ctx context.Context, evidenceID domain.EvidenceID, reference domain.ArtifactReference, payload []byte) (application.StagedArtifact, error) {
	if err := ctx.Err(); err != nil {
		return application.StagedArtifact{}, err
	}
	if evidenceID == "" {
		return application.StagedArtifact{}, fmt.Errorf("evidence identifier is required")
	}
	if err := store.validatePayload(reference, payload); err != nil {
		return application.StagedArtifact{}, err
	}
	token, err := randomToken()
	if err != nil {
		return application.StagedArtifact{}, fmt.Errorf("create artifact staging token: %w", err)
	}
	_, err = store.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(store.stageKey(token)),
		Body: bytes.NewReader(payload), ContentLength: aws.Int64(int64(len(payload))),
		ContentType: aws.String(reference.MediaType), Metadata: store.metadata(reference),
		IfNoneMatch: aws.String("*"),
	})
	if err != nil {
		return application.StagedArtifact{}, fmt.Errorf("stage R2 artifact: %w", err)
	}
	return application.StagedArtifact{ID: application.ArtifactStageID(token), EvidenceID: evidenceID, Reference: reference}, nil
}

func (store *R2Store) Promote(ctx context.Context, staged application.StagedArtifact) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	token, err := validateStagedArtifact(staged)
	if err != nil {
		return err
	}
	payload, err := store.readKey(ctx, store.stageKey(token), staged.Reference)
	if err != nil {
		return fmt.Errorf("verify staged R2 artifact: %w", err)
	}
	finalKey := store.objectKey(staged.Reference)
	_, err = store.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(finalKey),
		Body: bytes.NewReader(payload), ContentLength: aws.Int64(int64(len(payload))),
		ContentType: aws.String(staged.Reference.MediaType), Metadata: store.metadata(staged.Reference),
		IfNoneMatch: aws.String("*"),
	})
	if err != nil {
		if !r2PreconditionFailed(err) {
			return fmt.Errorf("promote R2 artifact: %w", err)
		}
		if _, readErr := store.readKey(ctx, finalKey, staged.Reference); readErr != nil {
			return fmt.Errorf("%w: existing R2 object failed verification", application.ErrArtifactConflict)
		}
	}
	if _, err := store.readKey(ctx, finalKey, staged.Reference); err != nil {
		return fmt.Errorf("verify promoted R2 artifact: %w", err)
	}
	if _, err := store.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(store.bucket), Key: aws.String(store.stageKey(token))}); err != nil {
		return fmt.Errorf("remove promoted R2 staging object: %w", err)
	}
	return nil
}

func (store *R2Store) Discard(ctx context.Context, staged application.StagedArtifact) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	token, err := validateStagedArtifact(staged)
	if err != nil {
		return err
	}
	_, err = store.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(store.bucket), Key: aws.String(store.stageKey(token))})
	if err != nil {
		return fmt.Errorf("discard staged R2 artifact: %w", err)
	}
	return nil
}

func (store *R2Store) Read(ctx context.Context, reference domain.ArtifactReference) ([]byte, error) {
	if err := domain.ValidateArtifactReference(reference); err != nil {
		return nil, err
	}
	return store.readKey(ctx, store.objectKey(reference), reference)
}

func (store *R2Store) Check(ctx context.Context, reference domain.ArtifactReference) (domain.ArtifactAvailability, error) {
	_, err := store.Read(ctx, reference)
	switch {
	case err == nil:
		return domain.ArtifactAvailable, nil
	case errors.Is(err, application.ErrArtifactUnavailable):
		return domain.ArtifactUnavailable, nil
	case errors.Is(err, application.ErrArtifactCorrupt), errors.Is(err, application.ErrArtifactTooLarge):
		return domain.ArtifactCorrupt, nil
	default:
		return "", err
	}
}

// Probe verifies the configured R2 token's write, read, and delete authority
// using only a random temporary key. It never creates a durable evidence object.
func (store *R2Store) Probe(ctx context.Context) error {
	payload := []byte("sherlock-r2-artifact-probe-v1")
	reference, err := domain.NewArtifactReference(
		domain.ChecksumSHA256(payload), int64(len(payload)), "text/plain",
		domain.ArtifactUncompressed, "r2-probe-v1",
		domain.RedactionSummary{PolicyVersion: "r2-probe-v1"}, domain.ArtifactRetentionStandard,
	)
	if err != nil {
		return fmt.Errorf("construct R2 probe: %w", err)
	}
	staged, err := store.Stage(ctx, "r2-probe", reference, payload)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = store.Discard(cleanupCtx, staged)
		}
	}()
	if _, err := store.readKey(ctx, store.stageKey(string(staged.ID)), reference); err != nil {
		return fmt.Errorf("verify R2 probe read: %w", err)
	}
	if err := store.Discard(ctx, staged); err != nil {
		return err
	}
	cleanup = false
	if _, err := store.readKey(ctx, store.stageKey(string(staged.ID)), reference); !errors.Is(err, application.ErrArtifactUnavailable) {
		return fmt.Errorf("verify R2 probe deletion")
	}
	return nil
}

// ImportContentAddressed verifies and creates one immutable object from a
// trusted local migration source. It never overwrites an existing object.
// The boolean is false for an already-present, checksum-identical replay.
func (store *R2Store) ImportContentAddressed(ctx context.Context, payload []byte) (bool, error) {
	if int64(len(payload)) > store.maxBytes {
		return false, application.ErrArtifactTooLarge
	}
	reference, err := domain.NewArtifactReference(
		domain.ChecksumSHA256(payload), int64(len(payload)), "application/octet-stream",
		domain.ArtifactUncompressed, "artifact-migration-v1",
		domain.RedactionSummary{PolicyVersion: "artifact-migration-v1"}, domain.ArtifactRetentionStandard,
	)
	if err != nil {
		return false, err
	}
	key := store.objectKey(reference)
	_, err = store.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(key), Body: bytes.NewReader(payload),
		ContentLength: aws.Int64(int64(len(payload))), ContentType: aws.String("application/octet-stream"),
		Metadata: store.metadata(reference), IfNoneMatch: aws.String("*"),
	})
	created := err == nil
	if err != nil && !r2PreconditionFailed(err) {
		return false, fmt.Errorf("import R2 artifact: %w", err)
	}
	if _, err := store.readKey(ctx, key, reference); err != nil {
		if created {
			return false, fmt.Errorf("verify imported R2 artifact: %w", err)
		}
		return false, fmt.Errorf("%w: existing R2 object failed verification", application.ErrArtifactConflict)
	}
	return created, nil
}

func (store *R2Store) readKey(ctx context.Context, key string, reference domain.ArtifactReference) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	output, err := store.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(store.bucket), Key: aws.String(key)})
	if err != nil {
		if r2NotFound(err) {
			return nil, application.ErrArtifactUnavailable
		}
		return nil, fmt.Errorf("read R2 object: %w", err)
	}
	if output == nil || output.Body == nil {
		return nil, application.ErrArtifactCorrupt
	}
	defer output.Body.Close()
	if output.ContentLength != nil && (*output.ContentLength > store.maxBytes || *output.ContentLength != reference.Bytes) {
		return nil, application.ErrArtifactCorrupt
	}
	payload, err := io.ReadAll(io.LimitReader(output.Body, store.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read R2 object body: %w", err)
	}
	if int64(len(payload)) > store.maxBytes {
		return nil, application.ErrArtifactTooLarge
	}
	if int64(len(payload)) != reference.Bytes || domain.ChecksumSHA256(payload) != reference.SHA256 {
		return nil, application.ErrArtifactCorrupt
	}
	return payload, nil
}

func (store *R2Store) validatePayload(reference domain.ArtifactReference, payload []byte) error {
	if err := domain.ValidateArtifactReference(reference); err != nil {
		return err
	}
	if int64(len(payload)) > store.maxBytes || reference.Bytes > store.maxBytes {
		return application.ErrArtifactTooLarge
	}
	if int64(len(payload)) != reference.Bytes || domain.ChecksumSHA256(payload) != reference.SHA256 {
		return application.ErrArtifactChecksumMismatch
	}
	return nil
}

func (store *R2Store) metadata(reference domain.ArtifactReference) map[string]string {
	return map[string]string{"sha256": reference.SHA256.String(), "bytes": strconv.FormatInt(reference.Bytes, 10)}
}

func (store *R2Store) stageKey(token string) string { return store.key("tmp", token) }

func (store *R2Store) objectKey(reference domain.ArtifactReference) string {
	digest := reference.SHA256.String()
	return store.key("objects", "sha256", digest[:2], digest)
}

func (store *R2Store) key(parts ...string) string {
	if store.prefix == "" {
		return path.Join(parts...)
	}
	return path.Join(append([]string{store.prefix}, parts...)...)
}

func validateStagedArtifact(staged application.StagedArtifact) (string, error) {
	token := string(staged.ID)
	if token == "" || path.Base(token) != token || strings.ContainsAny(token, `/\\`) {
		return "", fmt.Errorf("artifact staging identifier is invalid")
	}
	if staged.EvidenceID == "" {
		return "", fmt.Errorf("staged artifact evidence identifier is required")
	}
	if err := domain.ValidateArtifactReference(staged.Reference); err != nil {
		return "", err
	}
	return token, nil
}

func r2NotFound(err error) bool { return r2ErrorMatches(err, 404, "NoSuchKey", "NotFound") }

func r2PreconditionFailed(err error) bool {
	return r2ErrorMatches(err, 409, "ConditionalRequestConflict") || r2ErrorMatches(err, 412, "PreconditionFailed")
}

func r2ErrorMatches(err error, status int, codes ...string) bool {
	var responseError *smithyhttp.ResponseError
	if errors.As(err, &responseError) && responseError.HTTPStatusCode() == status {
		return true
	}
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		for _, code := range codes {
			if apiError.ErrorCode() == code {
				return true
			}
		}
	}
	return false
}
