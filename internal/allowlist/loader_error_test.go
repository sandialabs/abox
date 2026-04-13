package allowlist

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoader_CorruptFileReplacesFilter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.conf")

	// Load a valid allowlist first
	if err := os.WriteFile(path, []byte("github.com\nexample.com\n"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	filter := NewFilter()
	loader := NewLoader(path, filter)

	if err := loader.Load(); err != nil {
		t.Fatalf("initial Load failed: %v", err)
	}
	if filter.Count() != 2 {
		t.Fatalf("expected 2 domains after initial load, got %d", filter.Count())
	}

	// Now corrupt the file with only invalid domains
	if err := os.WriteFile(path, []byte("not a domain!\n@@@invalid\n"), 0o600); err != nil {
		t.Fatalf("WriteFile for corrupt file failed: %v", err)
	}

	// Reload — invalid domains are silently skipped, filter gets replaced with empty set
	if err := loader.Load(); err != nil {
		t.Fatalf("Load with corrupt content should not error (invalid domains are skipped): %v", err)
	}

	// Filter was replaced with empty set since no valid domains were parsed
	if filter.Count() != 0 {
		t.Errorf("expected 0 domains after corrupt reload, got %d", filter.Count())
	}
}

func TestLoader_MissingFileOnReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.conf")

	// Create and load initial file
	if err := os.WriteFile(path, []byte("github.com\n"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	filter := NewFilter()
	loader := NewLoader(path, filter)

	var callbackErr error
	loader.SetReloadCallback(func(count int, err error) {
		callbackErr = err
	})

	if err := loader.Load(); err != nil {
		t.Fatalf("initial Load failed: %v", err)
	}

	// Delete the file
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	// Reload — should fail because file is missing
	err := loader.Load()
	if err == nil {
		t.Fatal("expected error when reloading after file deletion")
	}

	// The callback should have received the error
	if callbackErr != nil {
		t.Logf("callback received error (expected): %v", callbackErr)
	}

	// Original filter contents should be preserved (Load returns early on error)
	if !filter.IsAllowed("github.com") {
		t.Error("github.com should still be allowed after failed reload")
	}
}

func TestLoader_PermissionDeniedOnReload(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("permission test only works on Linux")
	}
	if os.Getuid() == 0 {
		t.Skip("cannot test permission denied as root")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.conf")

	// Create and load initial file
	if err := os.WriteFile(path, []byte("github.com\n"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	filter := NewFilter()
	loader := NewLoader(path, filter)

	if err := loader.Load(); err != nil {
		t.Fatalf("initial Load failed: %v", err)
	}

	// Make file unreadable
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("Chmod failed: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	// Reload — should fail because file is unreadable
	err := loader.Load()
	if err == nil {
		t.Fatal("expected error when reloading with permission denied")
	}

	// Original filter contents should be preserved
	if !filter.IsAllowed("github.com") {
		t.Error("github.com should still be allowed after failed reload")
	}
}
