package allowlist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDomainSet_NormalizationEquivalence(t *testing.T) {
	// Wildcard, mixed-case, and trailing-dot spellings must collapse to the
	// same canonical entry.
	a := DomainSet([]string{"*.example.com", "API.Example.net", "example.org."})
	b := DomainSet([]string{"example.com", "api.example.net", "example.org"})
	if !DomainSetsEqual(a, b) {
		t.Errorf("expected equal sets after normalization:\n a=%v\n b=%v", a, b)
	}
}

func TestDomainSet_SkipsBlanks(t *testing.T) {
	set := DomainSet([]string{"example.com", "", "   "})
	if len(set) != 1 {
		t.Errorf("expected 1 entry, got %d: %v", len(set), set)
	}
}

func TestLoadDomainSet_MissingFileIsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.conf")

	set, err := LoadDomainSet(path)
	if err != nil {
		t.Fatalf("LoadDomainSet on missing file should not error, got: %v", err)
	}
	if len(set) != 0 {
		t.Errorf("expected empty set for missing file, got %v", set)
	}
}

func TestRenderDomainSet_SortedOnePerLine(t *testing.T) {
	got := RenderDomainSet(DomainSet([]string{"example.com", "api.example.net", "example.org"}))
	want := "api.example.net\nexample.com\nexample.org\n"
	if got != want {
		t.Errorf("RenderDomainSet = %q, want %q", got, want)
	}
	if RenderDomainSet(map[string]bool{}) != "" {
		t.Errorf("empty set should render to empty string")
	}
}

func TestLoadDomainSet_MatchesDeclaration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.conf")
	content := "# comment\n*.example.com\n\napi.example.net\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	onDisk, err := LoadDomainSet(path)
	if err != nil {
		t.Fatalf("LoadDomainSet failed: %v", err)
	}
	declared := DomainSet([]string{"example.com", "api.example.net"})
	if !DomainSetsEqual(onDisk, declared) {
		t.Errorf("on-disk set should equal declaration:\n disk=%v\n declared=%v", onDisk, declared)
	}
}
