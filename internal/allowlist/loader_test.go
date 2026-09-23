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

// TestLoader_Load_TrailingDotNormalized pins the behavior added when parseFile
// was refactored onto canonicalAllowlistEntry: an FQDN entry with a trailing dot
// ("example.net.") must load identically to the bare form, matching the ASCII
// form DNS queries arrive in. A regression here would silently fail to allow a
// dotted allowlist entry.
func TestLoader_Load_TrailingDotNormalized(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.conf")
	if err := os.WriteFile(path, []byte("example.net.\n*.example.com.\n"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	filter := NewFilter()
	loader := NewLoader(path, filter)
	if err := loader.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !filter.IsAllowed("example.net") {
		t.Error("example.net should be allowed from a trailing-dot entry")
	}
	// Trailing dot + wildcard prefix both stripped.
	if !filter.IsAllowed("example.com") {
		t.Error("example.com should be allowed from a trailing-dot wildcard entry")
	}
	if !filter.IsAllowed("sub.example.com") {
		t.Error("sub.example.com should be allowed (subdomain)")
	}

	// The parsed set must match the un-dotted declaration exactly.
	onDisk, err := LoadDomainSet(path)
	if err != nil {
		t.Fatalf("LoadDomainSet failed: %v", err)
	}
	if !DomainSetsEqual(onDisk, DomainSet([]string{"example.net", "example.com"})) {
		t.Errorf("trailing-dot entries should normalize to bare form, got %v", onDisk)
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

func TestRemoveDomain_ExactMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.conf")
	content := "example.com\napi.example.net\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	loader := NewLoader(path, NewFilter())
	removed, err := loader.RemoveDomain("example.com")
	if err != nil {
		t.Fatalf("RemoveDomain failed: %v", err)
	}
	if !removed {
		t.Fatal("expected removed=true for present domain")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	got := string(data)
	if strings.Contains(got, "example.com") {
		t.Errorf("example.com should be gone from file, got:\n%s", got)
	}
	if !strings.Contains(got, "api.example.net") {
		t.Errorf("api.example.net should be preserved, got:\n%s", got)
	}
}

func TestRemoveDomain_WildcardAndBareEquivalence(t *testing.T) {
	// A "*.foo.example" entry must be removed by a bare "foo.example" request, and
	// a mixed-case request must match the normalized stored form.
	tests := []struct {
		name    string
		stored  string // the line written to the file
		request string // the argument to RemoveDomain
	}{
		{"wildcard stored, bare request", "*.foo.example", "foo.example"},
		{"bare stored, wildcard request", "foo.example", "*.foo.example"},
		{"mixed case stored, lower request", "Foo.Example", "foo.example"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "allowlist.conf")
			if err := os.WriteFile(path, []byte(tt.stored+"\nkeep.example.net\n"), 0o600); err != nil {
				t.Fatalf("WriteFile failed: %v", err)
			}

			loader := NewLoader(path, NewFilter())
			removed, err := loader.RemoveDomain(tt.request)
			if err != nil {
				t.Fatalf("RemoveDomain failed: %v", err)
			}
			if !removed {
				t.Fatalf("expected removed=true (stored %q, request %q)", tt.stored, tt.request)
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile failed: %v", err)
			}
			got := string(data)
			if strings.Contains(strings.ToLower(got), "foo.example") {
				t.Errorf("target should be gone, got:\n%s", got)
			}
			if !strings.Contains(got, "keep.example.net") {
				t.Errorf("keep.example.net should be preserved, got:\n%s", got)
			}
		})
	}
}

func TestRemoveDomain_PreservesCommentsAndOrdering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.conf")
	content := "# header comment\n\nalpha.example\nexample.com\n  # indented note\nbeta.example\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	loader := NewLoader(path, NewFilter())
	if _, err := loader.RemoveDomain("example.com"); err != nil {
		t.Fatalf("RemoveDomain failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	want := "# header comment\n\nalpha.example\n  # indented note\nbeta.example\n"
	if string(data) != want {
		t.Errorf("file not preserved as expected.\n got:\n%q\nwant:\n%q", string(data), want)
	}
}

// TestRemoveDomain_NormalizesTrailingNewline documents the one way RemoveDomain
// is not byte-for-byte: kept lines are re-emitted newline-terminated, so a file
// whose final line lacked a trailing newline gains one. The allowlist is
// machine-managed and the parser is newline-agnostic, so this is intentional.
func TestRemoveDomain_NormalizesTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.conf")
	// No trailing newline on the last line.
	if err := os.WriteFile(path, []byte("example.com\nkeep.example"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	loader := NewLoader(path, NewFilter())
	removed, err := loader.RemoveDomain("example.com")
	if err != nil {
		t.Fatalf("RemoveDomain failed: %v", err)
	}
	if !removed {
		t.Fatal("expected removed=true")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if want := "keep.example\n"; string(data) != want {
		t.Errorf("kept line should be newline-terminated.\n got: %q\nwant: %q", string(data), want)
	}
}

func TestRemoveDomain_NotFoundIsNoOp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.conf")
	content := "example.com\napi.example.net\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	loader := NewLoader(path, NewFilter())
	removed, err := loader.RemoveDomain("absent.example.org")
	if err != nil {
		t.Fatalf("RemoveDomain failed: %v", err)
	}
	if removed {
		t.Error("expected removed=false for absent domain")
	}

	// File must be byte-for-byte unchanged when nothing matched.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(data) != content {
		t.Errorf("file should be unchanged, got:\n%q", string(data))
	}
}

func TestRemoveDomain_PreservesPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.conf")
	if err := os.WriteFile(path, []byte("example.com\nkeep.example\n"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	loader := NewLoader(path, NewFilter())
	if _, err := loader.RemoveDomain("example.com"); err != nil {
		t.Fatalf("RemoveDomain failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("file permissions too open after rewrite: %o", perm)
	}
}
