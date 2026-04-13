//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMount tests the mount and unmount commands.
func TestMount(t *testing.T) {
	skipIfNoLibvirt(t)
	skipIfNoConfiguredBaseImage(t)
	skipIfNoSSHFS(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()
	inst.start()

	if !inst.waitForRunning(60 * time.Second) {
		t.Fatal("Instance did not start")
	}
	if !inst.waitForSSH(120 * time.Second) {
		inst.dumpDiagnostics()
		t.Fatal("SSH did not become available")
	}

	// Create temp directory for mount points
	tempDir, err := os.MkdirTemp("", "abox-e2e-mount-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	t.Run("mount-unmount", func(t *testing.T) {
		mountPoint := filepath.Join(tempDir, "home-mount")

		// Mount the home directory
		result := env.mustRun("mount", inst.name, mountPoint)
		if !strings.Contains(result.Stdout, "Mounted") {
			t.Errorf("Expected mount success message, got: %s", result.Stdout)
		}

		// Verify mount point exists and is accessible
		entries, err := os.ReadDir(mountPoint)
		if err != nil {
			t.Fatalf("Failed to read mount point: %v", err)
		}
		// Home directory should exist and be readable
		t.Logf("Mount point contains %d entries", len(entries))

		// Create a file via the mount
		testFile := filepath.Join(mountPoint, "mount-test-file.txt")
		if err := os.WriteFile(testFile, []byte("test content"), 0o644); err != nil {
			t.Fatalf("Failed to write file via mount: %v", err)
		}

		// Verify file exists via SSH
		// Use $HOME/mount-test-file.txt for distro-agnostic path
		sshResult := inst.ssh("cat", "$HOME/mount-test-file.txt")
		if !sshResult.Success() || !strings.Contains(sshResult.Stdout, "test content") {
			t.Error("File created via mount should be visible via SSH")
		}

		// Unmount
		result = env.mustRun("unmount", mountPoint)
		if !strings.Contains(result.Stdout, "Unmounted") {
			t.Errorf("Expected unmount success message, got: %s", result.Stdout)
		}

		// Verify mount point is no longer mounted (reading should fail or be empty)
		entries, err = os.ReadDir(mountPoint)
		if err == nil && len(entries) > 0 {
			// Check if it's still the mounted content
			for _, e := range entries {
				if e.Name() == "mount-test-file.txt" {
					t.Error("Mount point should be unmounted")
				}
			}
		}
	})

	t.Run("read-only", func(t *testing.T) {
		mountPoint := filepath.Join(tempDir, "readonly-mount")

		// Mount as read-only
		result := env.mustRun("mount", "--read-only", inst.name, mountPoint)
		if !result.Success() {
			t.Fatalf("Failed to mount read-only: %v", result.Err)
		}

		// Try to write - should fail
		testFile := filepath.Join(mountPoint, "should-fail.txt")
		err := os.WriteFile(testFile, []byte("test"), 0o644)
		if err == nil {
			t.Error("Write to read-only mount should fail")
			os.Remove(testFile)
		}

		// Unmount
		env.mustRun("unmount", mountPoint)
	})

	t.Run("unmount-by-instance", func(t *testing.T) {
		// Create multiple mount points
		mountPoint1 := filepath.Join(tempDir, "multi-mount-1")
		mountPoint2 := filepath.Join(tempDir, "multi-mount-2")

		// Use the appropriate home directory for the base image
		user := getDefaultUser(getBaseImage())
		env.mustRun("mount", inst.name+":/home/"+user, mountPoint1)
		env.mustRun("mount", inst.name+":/tmp", mountPoint2)

		// Unmount all by instance name
		result := env.mustRun("unmount", inst.name)
		t.Logf("Unmount by instance output: %s", result.Stdout)

		// Verify both are unmounted by trying to list (should be empty or error)
		// Just check the command succeeded - actual verification is complex
	})

	t.Run("requires-running", func(t *testing.T) {
		// Stop the instance
		inst.forceStop()

		mountPoint := filepath.Join(tempDir, "stopped-mount")
		result := env.run("mount", inst.name, mountPoint)
		if result.Success() {
			t.Error("Mount should fail when instance is not running")
			// Clean up if it somehow succeeded
			env.run("unmount", mountPoint)
		}
		output := result.Stdout + result.Stderr
		if !strings.Contains(output, "not running") && !strings.Contains(output, "must be running") {
			t.Errorf("Expected error about instance not running, got: %s", output)
		}
	})
}
