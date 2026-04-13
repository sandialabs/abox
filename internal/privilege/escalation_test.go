package privilege

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSelectEscalationTool(t *testing.T) {
	// Create fake binaries so exec.LookPath can find them
	bothDir := t.TempDir()
	for _, name := range []string{"sudo", "pkexec"} {
		if err := os.WriteFile(filepath.Join(bothDir, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sudoOnlyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sudoOnlyDir, "sudo"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	pkexecOnlyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pkexecOnlyDir, "pkexec"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	emptyDir := t.TempDir()

	t.Run("user override is respected even when auto-detect would choose differently", func(t *testing.T) {
		// On a graphical system, auto-detect would pick pkexec.
		// But user explicitly asked for sudo — that should win.
		t.Setenv("PATH", bothDir)
		t.Setenv("DISPLAY", ":0")
		t.Setenv("ABOX_PRIVILEGE_METHOD", "sudo")

		tool, err := SelectEscalationTool()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tool != "sudo" {
			t.Errorf("user requested sudo but got %q", tool)
		}
	})

	t.Run("user override rejects unknown methods", func(t *testing.T) {
		t.Setenv("ABOX_PRIVILEGE_METHOD", "doas")

		_, err := SelectEscalationTool()
		if err == nil {
			t.Fatal("should reject unsupported escalation methods")
		}
	})

	t.Run("user override fails if requested tool is not installed", func(t *testing.T) {
		t.Setenv("PATH", emptyDir)
		t.Setenv("ABOX_PRIVILEGE_METHOD", "sudo")

		_, err := SelectEscalationTool()
		if err == nil {
			t.Fatal("should fail when the user-requested tool is not in PATH")
		}
	})

	t.Run("graphical session prefers pkexec for password dialog", func(t *testing.T) {
		t.Setenv("PATH", bothDir)
		t.Setenv("ABOX_PRIVILEGE_METHOD", "")
		t.Setenv("DISPLAY", ":0")
		t.Setenv("WAYLAND_DISPLAY", "")

		tool, err := SelectEscalationTool()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tool != "pkexec" {
			t.Errorf("graphical session should use pkexec, got %q", tool)
		}
	})

	t.Run("wayland session also gets pkexec", func(t *testing.T) {
		t.Setenv("PATH", bothDir)
		t.Setenv("ABOX_PRIVILEGE_METHOD", "")
		t.Setenv("DISPLAY", "")
		t.Setenv("WAYLAND_DISPLAY", "wayland-0")

		tool, err := SelectEscalationTool()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tool != "pkexec" {
			t.Errorf("wayland session should use pkexec, got %q", tool)
		}
	})

	t.Run("headless server uses sudo since pkexec needs a polkit agent", func(t *testing.T) {
		t.Setenv("PATH", bothDir)
		t.Setenv("ABOX_PRIVILEGE_METHOD", "")
		t.Setenv("DISPLAY", "")
		t.Setenv("WAYLAND_DISPLAY", "")

		tool, err := SelectEscalationTool()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tool != "sudo" {
			t.Errorf("headless server should use sudo, got %q", tool)
		}
	})

	t.Run("graphical session falls back to sudo if pkexec not installed", func(t *testing.T) {
		t.Setenv("PATH", sudoOnlyDir)
		t.Setenv("ABOX_PRIVILEGE_METHOD", "")
		t.Setenv("DISPLAY", ":0")

		tool, err := SelectEscalationTool()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tool != "sudo" {
			t.Errorf("should fall back to sudo, got %q", tool)
		}
	})

	t.Run("headless system with only pkexec still works as last resort", func(t *testing.T) {
		t.Setenv("PATH", pkexecOnlyDir)
		t.Setenv("ABOX_PRIVILEGE_METHOD", "")
		t.Setenv("DISPLAY", "")
		t.Setenv("WAYLAND_DISPLAY", "")

		tool, err := SelectEscalationTool()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tool != "pkexec" {
			t.Errorf("should use pkexec as last resort, got %q", tool)
		}
	})

	t.Run("fails clearly when neither tool is installed", func(t *testing.T) {
		t.Setenv("PATH", emptyDir)
		t.Setenv("ABOX_PRIVILEGE_METHOD", "")
		t.Setenv("DISPLAY", "")
		t.Setenv("WAYLAND_DISPLAY", "")

		_, err := SelectEscalationTool()
		if err == nil {
			t.Fatal("should fail when no privilege escalation tool is available")
		}
	})
}
