package secretstore

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSetListLoadRoundtrip(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "secrets"))

	if err := s.Set("anthropic", "sk-ant-123"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Set("openai", "sk-openai-456"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	m, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if m["anthropic"] != "sk-ant-123" || m["openai"] != "sk-openai-456" {
		t.Fatalf("roundtrip mismatch: %#v", m)
	}

	keys, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 2 || keys[0] != "anthropic" || keys[1] != "openai" {
		t.Fatalf("List() = %v, want sorted [anthropic openai]", keys)
	}
}

func TestSetOverwriteAndDelete(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "secrets"))
	if err := s.Set("k", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("k", "v2"); err != nil {
		t.Fatal(err)
	}
	m, _ := s.Load()
	if m["k"] != "v2" {
		t.Fatalf("overwrite failed: %q", m["k"])
	}
	if err := s.Delete("k"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("k"); err != nil {
		t.Fatalf("Delete of absent key should be nil: %v", err)
	}
	m, _ = s.Load()
	if _, ok := m["k"]; ok {
		t.Fatal("key still present after delete")
	}
}

func TestEmptyValueRoundtrips(t *testing.T) {
	// An empty value must survive Set→Load (the on-disk line is "key " with an
	// empty base64 field); it must not be silently dropped.
	s := New(filepath.Join(t.TempDir(), "secrets"))
	if err := s.Set("empty", ""); err != nil {
		t.Fatalf("Set empty: %v", err)
	}
	m, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	v, ok := m["empty"]
	if !ok {
		t.Fatalf("empty-valued key was dropped on reload: %#v", m)
	}
	if v != "" {
		t.Errorf("empty value round-tripped as %q", v)
	}
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "does-not-exist"))
	m, err := s.Load()
	if err != nil {
		t.Fatalf("Load of missing file: %v", err)
	}
	if len(m) != 0 {
		t.Fatalf("expected empty map, got %#v", m)
	}
}

func TestValueWithArbitraryBytes(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "secrets"))
	// Values with newlines/spaces must survive base64 encoding on disk.
	val := "line1\nline2 with spaces\ttab"
	if err := s.Set("weird", val); err != nil {
		t.Fatal(err)
	}
	m, _ := s.Load()
	if m["weird"] != val {
		t.Fatalf("arbitrary-byte value mangled: %q", m["weird"])
	}
}

func TestLargeSecretRoundtrips(t *testing.T) {
	// A secret whose base64 line exceeds bufio.Scanner's default 64KB cap must
	// still round-trip (e.g. a certificate bundle).
	s := New(filepath.Join(t.TempDir(), "secrets"))
	big := strings.Repeat("A", 200*1024) // 200KB raw -> ~267KB base64
	if err := s.Set("bundle", big); err != nil {
		t.Fatalf("Set big: %v", err)
	}
	m, err := s.Load()
	if err != nil {
		t.Fatalf("Load big: %v", err)
	}
	if m["bundle"] != big {
		t.Errorf("large secret mangled: got %d bytes, want %d", len(m["bundle"]), len(big))
	}
}

func TestInvalidKeyRejected(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "secrets"))
	for _, bad := range []string{"", "has space", "has-dash", "1leading", "dots.here", "nl\nkey"} {
		if err := s.Set(bad, "x"); err == nil {
			t.Errorf("Set(%q) should have failed", bad)
		}
	}
}

func TestFilePermissions(t *testing.T) {
	dir := t.TempDir()
	s := New(filepath.Join(dir, "sub", "secrets"))
	if err := s.Set("k", "v"); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("file perm = %o, want 0600", perm)
	}

	di, err := os.Stat(filepath.Dir(s.path))
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("dir perm = %o, want 0700", perm)
	}
}

func TestAtomicWriteLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	s := New(filepath.Join(dir, "secrets"))
	if err := s.Set("k", "v"); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "secrets" {
			t.Errorf("unexpected leftover file: %s", e.Name())
		}
	}
}

func TestReadSymlinkRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("O_NOFOLLOW semantics differ on windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("k dg==\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "secrets")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	s := New(link)
	if _, err := s.Load(); err == nil {
		t.Fatal("Load through a symlink should be rejected")
	}
}
