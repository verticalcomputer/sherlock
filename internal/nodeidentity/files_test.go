package nodeidentity

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func identityPath(t *testing.T) string { t.Helper(); return filepath.Join(t.TempDir(), "identity") }

func TestLocalIdentityRequestRestartAndInterruptedPublish(t *testing.T) {
	f := newFixture(t)
	path := identityPath(t)
	first, err := CreateIdentityRequest(path, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	keyBefore, err := os.ReadFile(filepath.Join(path, PrivateKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	second, err := CreateIdentityRequest(path, f.scope)
	if err != nil || first != second {
		t.Fatal("restart changed request", err)
	}
	if err := os.Remove(filepath.Join(path, RequestFile)); err != nil {
		t.Fatal(err)
	} // durable key, request publish interrupted
	resumed, err := CreateIdentityRequest(path, f.scope)
	if err != nil || resumed.PublicKeyBase64 != first.PublicKeyBase64 || resumed.CSRSHA256 != first.CSRSHA256 {
		t.Fatal("interrupted request replaced key", err)
	}
	keyAfter, _ := os.ReadFile(filepath.Join(path, PrivateKeyFile))
	if !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("regenerated durable key")
	}
	foreign := f.scope
	foreign.NodeID = "foreign"
	if _, err := CreateIdentityRequest(path, foreign); err == nil {
		t.Fatal("silently changed request scope")
	}
	for _, name := range []string{PrivateKeyFile, RequestFile, "identity.lock"} {
		stat, err := os.Stat(filepath.Join(path, name))
		if err != nil || stat.Mode().Perm() != 0o600 {
			t.Fatalf("bad file permissions %s", name)
		}
	}
	stat, _ := os.Stat(path)
	if stat.Mode().Perm() != 0o700 {
		t.Fatal("bad directory permissions")
	}
}

func TestLocalImportPreservesCurrentIdentityOnFailure(t *testing.T) {
	f := newFixture(t)
	path := identityPath(t)
	request, err := CreateIdentityRequest(path, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := f.issuer.Issue(request, f.at, MaxCertificateLifetime)
	if err != nil {
		t.Fatal(err)
	}
	if err := ImportIdentity(path, bundle, f.issuer.NodeCAFingerprint(), f.at); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(path, BundleFile))
	bad := bundle
	bad.Scope.NodeID = "foreign"
	if ImportIdentity(path, bad, f.issuer.NodeCAFingerprint(), f.at) == nil {
		t.Fatal("accepted foreign import")
	}
	after, _ := os.ReadFile(filepath.Join(path, BundleFile))
	if !bytes.Equal(before, after) {
		t.Fatal("failed import replaced current bundle")
	}
	loaded, key, err := LoadIdentity(path, f.issuer.NodeCAFingerprint(), f.at)
	if err != nil || loaded != bundle {
		t.Fatal("load failed", err)
	}
	if err := VerifyImport(loaded, request, key, f.issuer.NodeCAFingerprint(), f.at); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadIdentity(path, strings.Repeat("0", 64), f.at); err == nil {
		t.Fatal("loaded identity under unapproved trust")
	}
}

func TestLocalIdentityRejectsUnsafeFilesAndCorruption(t *testing.T) {
	f := newFixture(t)
	for _, test := range []struct {
		name   string
		change func(string)
	}{
		{"key permissions", func(path string) {
			if err := os.Chmod(filepath.Join(path, PrivateKeyFile), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory permissions", func(path string) {
			if err := os.Chmod(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"key symlink", func(path string) {
			target := filepath.Join(t.TempDir(), "outside")
			key, _ := os.ReadFile(filepath.Join(path, PrivateKeyFile))
			if err := os.WriteFile(target, key, 0o600); err != nil {
				t.Fatal(err)
			}
			_ = os.Remove(filepath.Join(path, PrivateKeyFile))
			if err := os.Symlink(target, filepath.Join(path, PrivateKeyFile)); err != nil {
				t.Fatal(err)
			}
		}},
		{"key hardlink", func(path string) {
			if err := os.Link(filepath.Join(path, PrivateKeyFile), filepath.Join(t.TempDir(), "hardlink")); err != nil {
				t.Fatal(err)
			}
		}},
		{"corrupt key", func(path string) {
			if err := os.WriteFile(filepath.Join(path, PrivateKeyFile), []byte("not a key"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing key", func(path string) {
			if err := os.Remove(filepath.Join(path, PrivateKeyFile)); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversize request", func(path string) {
			if err := os.WriteFile(filepath.Join(path, RequestFile), []byte(strings.Repeat("x", MaxRequestBytes+1)), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"ambiguous request", func(path string) {
			raw, _ := os.ReadFile(filepath.Join(path, RequestFile))
			raw = append(raw[:len(raw)-1], []byte(`,"protocol_version":1}`)...)
			if err := os.WriteFile(filepath.Join(path, RequestFile), raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := identityPath(t)
			if _, err := CreateIdentityRequest(path, f.scope); err != nil {
				t.Fatal(err)
			}
			test.change(path)
			if _, err := CreateIdentityRequest(path, f.scope); err == nil {
				t.Fatal("accepted unsafe identity")
			}
		})
	}
}

func TestLocalIdentityPersistentLockAndBundleSymlink(t *testing.T) {
	f := newFixture(t)
	path := identityPath(t)
	request, err := CreateIdentityRequest(path, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	d, err := openDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateIdentityRequest(path, f.scope); !errors.Is(err, ErrInUse) {
		t.Fatal("concurrent directory access not refused", err)
	}
	d.close()
	if _, err := CreateIdentityRequest(path, f.scope); err != nil {
		t.Fatal("lock not released", err)
	}
	if _, err := os.Stat(filepath.Join(path, "identity.lock")); err != nil {
		t.Fatal("persistent lock unlinked")
	}
	bundle, err := f.issuer.Issue(request, f.at, MaxCertificateLifetime)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "public")
	if err := os.WriteFile(outside, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(path, BundleFile)); err != nil {
		t.Fatal(err)
	}
	if ImportIdentity(path, bundle, f.issuer.NodeCAFingerprint(), f.at) == nil {
		t.Fatal("accepted symlink destination")
	}
	raw, _ := os.ReadFile(outside)
	if string(raw) != "preserve" {
		t.Fatal("overwrote symlink target")
	}
}

func TestLocalCorruptRequestNeverReplacesPrivateKey(t *testing.T) {
	f := newFixture(t)
	path := identityPath(t)
	if _, err := CreateIdentityRequest(path, f.scope); err != nil {
		t.Fatal(err)
	}
	keyBefore, _ := os.ReadFile(filepath.Join(path, PrivateKeyFile))
	data, _ := json.Marshal(f.request) // independently generated different private key
	if err := os.WriteFile(filepath.Join(path, RequestFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateIdentityRequest(path, f.scope); err == nil {
		t.Fatal("accepted mismatched durable CSR")
	}
	keyAfter, _ := os.ReadFile(filepath.Join(path, PrivateKeyFile))
	if !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("replaced key to match foreign request")
	}
}

func TestLocalIdentityRejectsUnsafeAncestorsBeforeCreating(t *testing.T) {
	f := newFixture(t)
	for _, mode := range []string{"symlink", "writable"} {
		t.Run(mode, func(t *testing.T) {
			base := t.TempDir()
			real := filepath.Join(base, "real")
			if err := os.Mkdir(real, 0o700); err != nil {
				t.Fatal(err)
			}
			ancestor := real
			if mode == "symlink" {
				ancestor = filepath.Join(base, "link")
				if err := os.Symlink(real, ancestor); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Chmod(real, 0o777); err != nil {
				t.Fatal(err)
			}
			if _, err := CreateIdentityRequest(filepath.Join(ancestor, "new", "identity"), f.scope); err == nil {
				t.Fatal("accepted unsafe ancestor")
			}
			if _, err := os.Stat(filepath.Join(real, "new")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("created data below unsafe ancestor")
			}
		})
	}
}
