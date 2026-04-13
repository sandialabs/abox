package allowlist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoader_Load(t *testing.T) {
	dir := t.TempDir()
	allowlistPath := filepath.Join(dir, "allowlist.conf")

	content := "github.com\n*.example.com\n# comment\n\napi.openai.com\n"
	if err := os.WriteFile(allowlistPath, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	filter := NewFilter()
	loader := NewLoader(allowlistPath, filter)

	if err := loader.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify filter has the domains
	if !filter.IsAllowed("github.com") {
		t.Error("github.com should be allowed")
	}
	if !filter.IsAllowed("api.openai.com") {
		t.Error("api.openai.com should be allowed")
	}
	// *.example.com should become example.com (wildcard stripped)
	if !filter.IsAllowed("example.com") {
		t.Error("example.com should be allowed (wildcard stripped)")
	}
	if !filter.IsAllowed("sub.example.com") {
		t.Error("sub.example.com should be allowed (subdomain of example.com)")
	}
}

func TestLoader_ParseFile_Comments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.conf")

	content := "# Full line comment\ngithub.com\n  # Indented comment\napi.example.com\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	filter := NewFilter()
	loader := NewLoader(path, filter)

	if err := loader.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !filter.IsAllowed("github.com") {
		t.Error("github.com should be allowed")
	}
	if !filter.IsAllowed("api.example.com") {
		t.Error("api.example.com should be allowed")
	}
}

func TestLoader_ParseFile_BlankLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.conf")

	content := "\n\ngithub.com\n\n\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	filter := NewFilter()
	loader := NewLoader(path, filter)

	if err := loader.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !filter.IsAllowed("github.com") {
		t.Error("github.com should be allowed")
	}
}

func TestLoader_ReloadCallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.conf")
	if err := os.WriteFile(path, []byte("a.com\nb.com\n"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	filter := NewFilter()
	loader := NewLoader(path, filter)

	var callbackCount int
	var callbackDomains int
	loader.SetReloadCallback(func(count int, err error) {
		callbackCount++
		callbackDomains = count
	})

	if err := loader.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if callbackCount != 1 {
		t.Errorf("callback called %d times, want 1", callbackCount)
	}
	if callbackDomains != 2 {
		t.Errorf("callback got %d domains, want 2", callbackDomains)
	}
}

func TestEnsureDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "allowlist.conf")

	if err := EnsureDir(path); err != nil {
		t.Fatalf("EnsureDir failed: %v", err)
	}

	// Check directory was created
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory")
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("directory permissions too open: %o", perm)
	}

	// Idempotent
	if err := EnsureDir(path); err != nil {
		t.Fatalf("second EnsureDir failed: %v", err)
	}
}

func TestSaveDomain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.conf")
	// Create initial file
	if err := os.WriteFile(path, []byte("existing.com\n"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	filter := NewFilter()
	loader := NewLoader(path, filter)

	if err := loader.SaveDomain("new.example.com"); err != nil {
		t.Fatalf("SaveDomain failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "existing.com") {
		t.Error("should preserve existing content")
	}
	if !strings.Contains(content, "new.example.com") {
		t.Error("should contain new domain")
	}
}

func TestSaveDomain_RejectNewlines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.conf")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	filter := NewFilter()
	loader := NewLoader(path, filter)

	if err := loader.SaveDomain("evil\ndomain.com"); err == nil {
		t.Fatal("expected error for domain with newline")
	}

	if err := loader.SaveDomain("evil\rdomain.com"); err == nil {
		t.Fatal("expected error for domain with carriage return")
	}
}
