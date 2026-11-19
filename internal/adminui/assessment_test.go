package adminui

import (
	"bytes"
	"encoding/json"
	"github.com/verticalcomputer/sherlock/internal/alertdelivery"
	"strings"
	"testing"
)

func TestAssessmentEvidenceRenderingEscapesContent(t *testing.T) {
	h := alertdelivery.ProductionNotificationHistory{Occurrence: alertdelivery.ProductionOccurrence{ClusterID: "c", Asset: "<script>alert(1)</script>", MaintenanceReason: "<img src=x onerror=alert(2)>"}, Events: []alertdelivery.ProductionNotificationEvent{{Summary: "<!here> concern", Evidence: json.RawMessage(`{"payload":"<script>evil</script>"}`)}}}
	data := struct {
		History                                alertdelivery.ProductionNotificationHistory
		Delivery, Audit, NextEvents, NextAudit string
	}{History: h, Delivery: "<script>bad</script>", NextEvents: "?after=3&after_audit=0"}
	var b bytes.Buffer
	if err := assessmentTemplate.Execute(&b, data); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, bad := range []string{"<script>", "<img src=x", "<!here>"} {
		if strings.Contains(s, bad) {
			t.Fatal("unescaped content", bad)
		}
	}
	if !strings.Contains(s, "No measured recovery recorded") || !strings.Contains(s, "Next events") {
		t.Fatal("missing condition or pagination")
	}
}
