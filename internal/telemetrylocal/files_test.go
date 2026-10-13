package telemetrylocal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProtectedInputRejectsUnsafeAliasesAndPermissions(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "input.json")
	if e := os.WriteFile(path, []byte("fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if b, e := ReadProtected(path, 32); e != nil || string(b) != "fixture" {
		t.Fatal(e)
	}
	for _, kind := range []string{"mode", "hardlink", "symlink", "ancestor", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			d := t.TempDir()
			p := filepath.Join(d, "input")
			_ = os.WriteFile(p, []byte("fixture"), 0600)
			switch kind {
			case "mode":
				_ = os.Chmod(p, 0640)
			case "hardlink":
				_ = os.Link(p, filepath.Join(d, "other"))
			case "symlink":
				other := filepath.Join(d, "alias")
				_ = os.Symlink(p, other)
				p = other
			case "ancestor":
				alias := filepath.Join(d, "alias")
				_ = os.Symlink(root, alias)
				p = filepath.Join(alias, "input.json")
			case "oversize":
				_ = os.WriteFile(p, make([]byte, 33), 0600)
			}
			if _, e := ReadProtected(p, 32); e == nil {
				t.Fatal("unsafe input accepted")
			}
		})
	}
}
func TestUnsafeDirectoryRejectedBeforeRead(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "unsafe")
	_ = os.Mkdir(d, 0777)
	_ = os.Chmod(d, 0777)
	p := filepath.Join(d, "input")
	_ = os.WriteFile(p, []byte("fixture"), 0600)
	if _, e := ReadProtected(p, 64); e == nil {
		t.Fatal("writable ancestor accepted")
	}
}

func TestNewOutputIsDurableOwnerOnlyAndNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if e := WriteNewProtected(path, []byte("first")); e != nil {
		t.Fatal(e)
	}
	if e := WriteNewProtected(path, []byte("second")); e == nil {
		t.Fatal("replaced output")
	}
	b, e := ReadProtected(path, 32)
	if e != nil || string(b) != "first" {
		t.Fatal(e)
	}
	info, e := os.Stat(path)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal(e)
	}
}
