package collectorcontrol

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

type retirementIntakeFake struct {
	fakeTelemetryIntake
	retirementCalls int
	foreign         bool
}

func (f *retirementIntakeFake) RetirementCapabilities(_ context.Context, c domain.ClusterID, g domain.CollectorID, _ string) (telemetry.RetirementCapabilities, error) {
	f.retirementCalls++
	f.cluster, f.collector = string(c), string(g)
	return telemetry.SupportedRetirementCapabilities(), f.err
}
func (f *retirementIntakeFake) PrepareRetirement(_ context.Context, c domain.ClusterID, g domain.CollectorID, r telemetry.ReleaseRequest, _ telemetry.ReleaseManifest, a telemetry.ReleaseAdmissionReceipt) (telemetry.CloudRetirementReceipt, error) {
	f.retirementCalls++
	f.cluster, f.collector = string(c), string(g)
	out := telemetry.CloudRetirementReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: "prepared-1", Phase: "PREPARED", Binding: r.Binding(), GatewayAdmissionID: a.ID, StoredAt: transportNow, Durability: "CLOUD"}
	if f.foreign {
		out.Binding.NodeID = "foreign"
	}
	return out, f.err
}
func (f *retirementIntakeFake) CommitRetirement(_ context.Context, _ domain.ClusterID, _ domain.CollectorID, r telemetry.ReleaseRequest, c telemetry.GatewayReleaseCommit) (telemetry.CloudRetirementReceipt, error) {
	f.retirementCalls++
	out := telemetry.CloudRetirementReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: "final-1", Phase: "FINAL", Binding: r.Binding(), GatewayAdmissionID: c.GatewayAdmissionID, PreparedReceiptID: c.PreparedReceiptID, GatewayCommitID: c.ID, StoredAt: transportNow, Durability: "CLOUD"}
	if f.foreign {
		out.GatewayCommitID = "foreign"
	}
	return out, f.err
}
func (f *retirementIntakeFake) CompleteRetirement(_ context.Context, _ domain.ClusterID, _ domain.CollectorID, c telemetry.NodeReleaseCompletion) (telemetry.NodeCompletionReceipt, error) {
	f.retirementCalls++
	out := telemetry.NodeCompletionReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: "completed-1", Binding: c.Binding, CompletionDigest: c.Digest, CloudFinalReceiptID: c.CloudFinalReceiptID, GatewayRetirementReceiptID: c.GatewayRetirementReceiptID, StoredAt: transportNow, Durability: "CLOUD"}
	if f.foreign {
		out.CompletionDigest = strings.Repeat("0", 64)
	}
	return out, f.err
}
func transportRelease(t *testing.T) telemetry.ReleasePrepareEnvelope {
	t.Helper()
	m := telemetry.ReleaseManifest{Batches: []telemetry.ReleaseBatchFact{{Sequence: "1", Digest: strings.Repeat("a", 64), GatewayReceiptID: "gateway-batch-1"}}}
	d, err := telemetry.CanonicalReleaseManifestDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	r := telemetry.ReleaseRequest{ProtocolVersion: 1, ReleaseVersion: 1, ReleaseID: "release-1", ClusterID: "cluster-1", NodeID: "node-a", EnrollmentID: "enrollment-a", EnrollmentRevision: 1, SessionEpoch: "1", SessionID: "session-1", SigningKeyID: "key-1", CreatedAt: transportNow, FromSequence: "1", ThroughSequence: "1", ManifestDigest: hex.EncodeToString(d[:])}
	if err := telemetry.SignReleaseRequest(&r, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))); err != nil {
		t.Fatal(err)
	}
	return telemetry.ReleasePrepareEnvelope{Release: telemetry.ReleaseEnvelope{Request: r, Manifest: m}, Admission: telemetry.ReleaseAdmissionReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: "admission-1", Binding: r.Binding(), StoredAt: transportNow, Durability: "GATEWAY"}}
}
func TestRetirementTransportAuthenticatesAndBoundsBeforeStore(t *testing.T) {
	e := transportRelease(t)
	wire, _ := json.Marshal(e)
	for _, tc := range []struct {
		name, body string
		auth       bool
		edit       func(*http.Request)
		code       int
	}{
		{"valid", string(wire), true, nil, 200},
		{"unauthenticated", string(wire), false, nil, 401},
		{"missing-release-version", string(wire), true, func(r *http.Request) { r.Header.Del("X-Sherlock-Release-Version") }, 426},
		{"duplicate-release-version", string(wire), true, func(r *http.Request) { r.Header.Add("X-Sherlock-Release-Version", "1") }, 426},
		{"oversize", strings.Repeat("x", telemetry.MaxReleaseBytes+1), true, nil, 413},
		{"unknown-key", strings.Replace(string(wire), `"request":`, `"command":"x","request":`, 1), true, nil, 400},
		{"query", string(wire), true, func(r *http.Request) { r.URL.RawQuery = "node=foreign" }, 400},
		{"encoding", string(wire), true, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, 415},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr, _, _, _, _ := newTestTransport(t)
			store := &retirementIntakeFake{}
			if err := tr.ConfigureTelemetry(store); err != nil {
				t.Fatal(err)
			}
			w := telemetryRequest(t, tr, "/collector/telemetry/v1/retirement/prepare", tc.body, tc.auth, func(r *http.Request) {
				r.Header.Set("X-Sherlock-Release-Version", "1")
				if tc.edit != nil {
					tc.edit(r)
				}
			})
			if w.Code != tc.code {
				t.Fatal(w.Code, w.Body.String())
			}
			if tc.code != 200 && store.retirementCalls != 0 {
				t.Fatal("rejected request reached store")
			}
			if tc.code == 200 && (store.cluster != "cluster-1" || store.collector != "collector-1") {
				t.Fatal("caller supplied authority")
			}
		})
	}
}
func TestRetirementTransportCannotPublishForeignPhaseReceipt(t *testing.T) {
	e := transportRelease(t)
	commit := telemetry.GatewayReleaseCommit{ProtocolVersion: 1, ReleaseVersion: 1, ID: "commit-1", Binding: e.Release.Request.Binding(), GatewayAdmissionID: e.Admission.ID, PreparedReceiptID: "prepared-1", CreatedAt: transportNow}
	c := telemetry.NodeReleaseCompletion{ProtocolVersion: 1, ReleaseVersion: 1, ID: "node-completion", Binding: e.Release.Request.Binding(), CloudFinalReceiptID: "final-1", GatewayRetirementReceiptID: "gateway-final", SigningKeyID: "key-1", CreatedAt: transportNow, Digest: strings.Repeat("a", 64)}
	for _, tc := range []struct {
		path  string
		value any
	}{{"prepare", e}, {"commit", telemetry.ReleaseCommitEnvelope{Request: e.Release.Request, Commit: commit}}, {"complete", c}} {
		tr, _, _, _, _ := newTestTransport(t)
		store := &retirementIntakeFake{foreign: true}
		if err := tr.ConfigureTelemetry(store); err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(tc.value)
		w := telemetryRequest(t, tr, "/collector/telemetry/v1/retirement/"+tc.path, string(body), true, func(r *http.Request) { r.Header.Set("X-Sherlock-Release-Version", "1") })
		if w.Code != 503 || store.retirementCalls != 1 {
			t.Fatal("foreign durable proof published", tc.path, w.Code, w.Body.String())
		}
	}
	tr, _, _, _, _ := newTestTransport(t)
	if err := tr.ConfigureTelemetry(&fakeTelemetryIntake{}); err != nil {
		t.Fatal(err)
	}
	w := telemetryRequest(t, tr, "/collector/telemetry/v1/enrollments/enrollment-a/retirement-capabilities", "", true, nil)
	if w.Code != 404 {
		t.Fatal("legacy store advertised retirement", w.Code)
	}
}
