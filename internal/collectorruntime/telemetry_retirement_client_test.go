package collectorruntime

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func retirementClientProof(t *testing.T) (telemetry.ReleasePrepareEnvelope, telemetry.GatewayReleaseCommit, telemetry.NodeReleaseCompletion) {
	t.Helper()
	m := telemetry.ReleaseManifest{Batches: []telemetry.ReleaseBatchFact{{Sequence: "1", Digest: strings.Repeat("a", 64), GatewayReceiptID: "batch-receipt"}}}
	d, err := telemetry.CanonicalReleaseManifestDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	r := telemetry.ReleaseRequest{ProtocolVersion: 1, ReleaseVersion: 1, ReleaseID: "release", ClusterID: "cluster-a", NodeID: "node-a", EnrollmentID: "enrollment-a", EnrollmentRevision: 1, SessionEpoch: "1", SessionID: "session-a", SigningKeyID: "key-a", CreatedAt: at, FromSequence: "1", ThroughSequence: "1", ManifestDigest: hex.EncodeToString(d[:])}
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	if err := telemetry.SignReleaseRequest(&r, key); err != nil {
		t.Fatal(err)
	}
	a := telemetry.ReleaseAdmissionReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: "admission", Binding: r.Binding(), StoredAt: at, Durability: "GATEWAY"}
	k := telemetry.GatewayReleaseCommit{ProtocolVersion: 1, ReleaseVersion: 1, ID: "commit", Binding: r.Binding(), GatewayAdmissionID: a.ID, PreparedReceiptID: "prepared", CreatedAt: at}
	c := telemetry.NodeReleaseCompletion{ProtocolVersion: 1, ReleaseVersion: 1, ID: "completion", Binding: r.Binding(), CloudFinalReceiptID: "final", GatewayRetirementReceiptID: "gateway-final", SigningKeyID: "key-a", CreatedAt: at}
	if err := telemetry.SignNodeCompletion(&c, key); err != nil {
		t.Fatal(err)
	}
	return telemetry.ReleasePrepareEnvelope{Release: telemetry.ReleaseEnvelope{Request: r, Manifest: m}, Admission: a}, k, c
}

func TestRetirementClientExactPhasesAndForeignReceipts(t *testing.T) {
	e, k, c := retirementClientProof(t)
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact", true: "foreign"}[foreign], func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Header.Get("X-Sherlock-Release-Version") != "1" || r.Header.Get("X-Sherlock-Telemetry-Version") != "1" || r.Header.Get(protocolHeader) != "1" || r.Header.Get("Accept-Encoding") != "identity" {
					t.Error("missing protocol fence")
				}
				b := e.Release.Request.Binding()
				if foreign {
					b.SessionID = "foreign"
				}
				switch r.URL.Path {
				case "/collector/telemetry/v1/enrollments/enrollment-a/retirement-capabilities":
					out := telemetry.SupportedRetirementCapabilities()
					if foreign {
						out.ReleaseVersion++
					}
					_ = json.NewEncoder(w).Encode(out)
				case "/collector/telemetry/v1/retirement/prepare":
					var got telemetry.ReleasePrepareEnvelope
					if json.NewDecoder(r.Body).Decode(&got) != nil || got.Release.Request != e.Release.Request || got.Admission != e.Admission {
						t.Error("prepare proof changed")
					}
					_ = json.NewEncoder(w).Encode(telemetry.CloudRetirementReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: "prepared", Phase: "PREPARED", Binding: b, GatewayAdmissionID: e.Admission.ID, StoredAt: k.CreatedAt, Durability: "CLOUD"})
				case "/collector/telemetry/v1/retirement/commit":
					var got telemetry.ReleaseCommitEnvelope
					if json.NewDecoder(r.Body).Decode(&got) != nil || got.Request != e.Release.Request || got.Commit != k {
						t.Error("commit proof changed")
					}
					_ = json.NewEncoder(w).Encode(telemetry.CloudRetirementReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: "final", Phase: "FINAL", Binding: b, GatewayAdmissionID: k.GatewayAdmissionID, PreparedReceiptID: k.PreparedReceiptID, GatewayCommitID: k.ID, StoredAt: k.CreatedAt, Durability: "CLOUD"})
				case "/collector/telemetry/v1/retirement/complete":
					var got telemetry.NodeReleaseCompletion
					if json.NewDecoder(r.Body).Decode(&got) != nil || got != c {
						t.Error("completion proof changed")
					}
					_ = json.NewEncoder(w).Encode(telemetry.NodeCompletionReceipt{ProtocolVersion: 1, ReleaseVersion: 1, ID: "completed", Binding: b, CompletionDigest: c.Digest, CloudFinalReceiptID: c.CloudFinalReceiptID, GatewayRetirementReceiptID: c.GatewayRetirementReceiptID, StoredAt: c.CreatedAt, Durability: "CLOUD"})
				default:
					t.Error("unexpected path")
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			client := newTelemetryTestClient(t, server)
			_, capErr := client.RetirementCapabilities(context.Background(), "enrollment-a")
			_, prepareErr := client.PrepareRetirement(context.Background(), e.Release.Request, e.Release.Manifest, e.Admission)
			_, commitErr := client.CommitRetirement(context.Background(), e.Release.Request, k)
			_, completeErr := client.CompleteRetirement(context.Background(), c)
			for _, err := range []error{capErr, prepareErr, commitErr, completeErr} {
				if (err != nil) != foreign {
					t.Fatal("phase receipt accepted incorrectly", err)
				}
			}
			if calls != 4 {
				t.Fatal("unexpected transport calls", calls)
			}
		})
	}
}
