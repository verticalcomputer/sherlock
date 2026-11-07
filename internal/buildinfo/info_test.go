package buildinfo

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestVersionIsExplicitAndDoesNotConsumeRuntimeArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"run"}, {"version", "extra"}} {
		if PrintVersion(args, &bytes.Buffer{}) {
			t.Fatalf("runtime arguments consumed: %v", args)
		}
	}
	var output bytes.Buffer
	if !PrintVersion([]string{"--version"}, &output) {
		t.Fatal("version not recognized")
	}
	var decoded map[string]string
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["source_revision"] != "UNVERIFIED" || decoded["source_tree"] != "UNVERIFIED" {
		t.Fatal("developer build falsely verified")
	}
}
