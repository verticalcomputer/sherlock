package controlplane

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/config"
)

func TestUploadSystemdTLSFixture(t *testing.T) {
	if os.Getenv("SHERLOCK_TEST_UPLOAD_SYSTEMD_TLS") != "1" {
		t.Skip("requires the isolated systemd-style credential fixture")
	}
	const directory = "/run/credentials/sherlock-upload-fixture.service"
	cfg := config.Control{ServerCertificate: filepath.Join(directory, "server.crt"),
		ServerPrivateKey: filepath.Join(directory, "server.key"), CollectorCA: filepath.Join(directory, "server.crt")}
	t.Setenv("CREDENTIALS_DIRECTORY", directory)
	if _, err := LoadPrometheusUploadTLSConfig(cfg); err != nil {
		t.Fatalf("named service UID ACL rejected: %v", err)
	}
	for _, name := range []string{"extra-user.key", "group-readable.key", "symlink.key"} {
		if _, err := readUploadServerKey(filepath.Join(directory, name)); err == nil {
			t.Fatalf("accepted unsafe key %s", name)
		}
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if _, err := LoadPrometheusUploadTLSConfig(cfg); err == nil {
		t.Fatal("accepted projected key outside the intended credential context")
	}
}
