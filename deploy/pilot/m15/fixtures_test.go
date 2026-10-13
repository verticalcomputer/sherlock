package m15_test

import (
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/remediation"
	yaml "go.yaml.in/yaml/v3"
)

// This validates the safety-critical manifest wiring without contacting a
// Kubernetes cluster. Environment-specific deployment still requires API dry-run.
func TestPilotManifestDefaultOff(t *testing.T) {
	b, err := os.ReadFile("remediator.yaml")
	if err != nil {
		t.Fatal(err)
	}
	d := yaml.NewDecoder(strings.NewReader(string(b)))
	docs := map[string]map[string]any{}
	for {
		var doc map[string]any
		err = d.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		docs[doc["kind"].(string)] = doc
	}
	deployment := docs["Deployment"]
	spec := deployment["spec"].(map[string]any)
	if spec["replicas"] != 0 {
		t.Fatal("pilot must default to zero replicas")
	}
	pod := spec["template"].(map[string]any)["spec"].(map[string]any)
	if pod["automountServiceAccountToken"] != false {
		t.Fatal("pilot must be tokenless")
	}
	containers := pod["containers"].([]any)
	if len(containers) != 1 {
		t.Fatal("unexpected container")
	}
	c := containers[0].(map[string]any)
	env := map[string]map[string]any{}
	for _, v := range c["env"].([]any) {
		e := v.(map[string]any)
		env[e["name"].(string)] = e
	}
	for _, name := range []string{"SHERLOCK_REMEDIATION_ENABLED", "SHERLOCK_REMEDIATION_EXECUTOR", "SHERLOCK_REMEDIATION_DATABASE_URL", "SHERLOCK_CLUSTER_ID", "SHERLOCK_REMEDIATION_BATCH", "SHERLOCK_REMEDIATION_POLL_INTERVAL", "SHERLOCK_REMEDIATION_WORKER_ID", "SHERLOCK_REMEDIATION_TRUST_ROOTS", "SHERLOCK_REMEDIATION_RELEASE"} {
		if env[name] == nil {
			t.Fatalf("missing %s", name)
		}
	}
	if env["SHERLOCK_REMEDIATION_ENABLED"]["value"] != "false" || env["SHERLOCK_REMEDIATION_EXECUTOR"]["value"] != "LIVE" {
		t.Fatal("unsafe enablement")
	}
	if env["SHERLOCK_DATABASE_URL"] != nil || env["SHERLOCK_REMEDIATION_DATABASE_URL"]["valueFrom"] == nil {
		t.Fatal("database must use dedicated secret reference")
	}
	if env["SHERLOCK_REMEDIATION_METRICS_ADDRESS"]["value"] != "127.0.0.1:9095" {
		t.Fatal("metrics must be private")
	}
	config := docs["ConfigMap"]["data"].(map[string]any)
	valid := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	for key := range config {
		if !valid.MatchString(key) {
			t.Fatalf("invalid ConfigMap key %s", key)
		}
	}
	volumes := pod["volumes"].([]any)
	items := volumes[0].(map[string]any)["configMap"].(map[string]any)["items"].([]any)
	paths := map[string]bool{}
	for _, v := range items {
		item := v.(map[string]any)
		if config[item["key"].(string)] == nil {
			t.Fatal("volume references absent key")
		}
		paths["/etc/sherlock/signing/"+item["path"].(string)] = true
	}
	if !paths[env["SHERLOCK_REMEDIATION_RELEASE"]["value"].(string)] || !paths[env["SHERLOCK_REMEDIATION_TRUST_ROOTS"]["value"].(string)] {
		t.Fatal("signing paths are not mounted")
	}
	policy := docs["NetworkPolicy"]["spec"].(map[string]any)
	if len(policy["ingress"].([]any)) != 0 || len(policy["egress"].([]any)) != 0 {
		t.Fatal("pilot must default deny network")
	}
	for _, bad := range []string{"postgres://", "PRIVATE KEY"} {
		if strings.Contains(string(b), bad) {
			t.Fatal("inline connection or private key")
		}
	}
}
func TestPolicyUsesVerifiedRecipeCoordinate(t *testing.T) {
	b, err := os.ReadFile("policy.one-stream.example.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{string(remediation.RecipeEvidenceCollectionRequeue), remediation.CollectionRequestRecipeVersion, "ROLLBACK;", "false,1"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("missing policy requirement %s", want)
		}
	}
}
