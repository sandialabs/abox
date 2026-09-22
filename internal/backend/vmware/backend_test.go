package vmware

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveStaleMonitorSocket(t *testing.T) {
	t.Run("removes a socket", func(t *testing.T) {
		dir := t.TempDir()
		sockPath := filepath.Join(dir, "monitor.sock")
		l, err := net.Listen("unix", sockPath)
		if err != nil {
			// Some sandboxed CI/dev environments forbid AF_UNIX bind; the guard
			// logic is still exercised by the other sub-tests.
			t.Skipf("cannot create unix socket in this environment: %v", err)
		}
		defer func() { _ = l.Close() }()

		if err := removeStaleMonitorSocket(sockPath); err != nil {
			t.Fatalf("removeStaleMonitorSocket: %v", err)
		}
		if _, err := os.Lstat(sockPath); !os.IsNotExist(err) {
			t.Errorf("expected socket removed, lstat err = %v", err)
		}
	})

	t.Run("missing path is fine", func(t *testing.T) {
		if err := removeStaleMonitorSocket(filepath.Join(t.TempDir(), "nope.sock")); err != nil {
			t.Errorf("expected nil for missing path, got %v", err)
		}
	})

	t.Run("leaves a non-socket untouched", func(t *testing.T) {
		dir := t.TempDir()
		regular := filepath.Join(dir, "monitor.sock")
		if err := os.WriteFile(regular, []byte("not a socket"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := removeStaleMonitorSocket(regular); err != nil {
			t.Fatalf("removeStaleMonitorSocket: %v", err)
		}
		if _, err := os.Stat(regular); err != nil {
			t.Errorf("expected regular file preserved, got %v", err)
		}
	})
}

func TestRequiredTools(t *testing.T) {
	b := &Backend{}
	got := make(map[string]bool)
	for _, tool := range b.RequiredTools() {
		got[tool.Name] = true
	}
	if !got["vmrun"] {
		t.Errorf("RequiredTools() missing %q; got %v", "vmrun", got)
	}
}

func TestMonitorTransport(t *testing.T) {
	b := New()
	mt := b.MonitorTransport()
	if mt == nil {
		t.Fatal("MonitorTransport() = nil, want non-nil")
	}
	// Must match the serial index used in the .vmx serial0 pipe (serial0 -> ttyS0).
	if got, want := mt.GuestDevice(), "/dev/ttyS0"; got != want {
		t.Errorf("GuestDevice() = %q, want %q", got, want)
	}
}
