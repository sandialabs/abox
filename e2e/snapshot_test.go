//go:build e2e

package e2e

import (
	"strings"
	"testing"
	"time"
)

// TestSnapshotLifecycle tests the full snapshot create -> list -> revert -> remove cycle.
func TestSnapshotLifecycle(t *testing.T) {
	skipIfNoLibvirt(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()

	snapshotName := "test-snap"

	t.Run("create", func(t *testing.T) {
		// Instance must be stopped to create snapshot
		result := env.mustRun("snapshot", "create", inst.name, snapshotName)
		if !strings.Contains(result.Stdout, "created successfully") {
			t.Errorf("Expected success message, got: %s", result.Stdout)
		}
	})

	t.Run("list", func(t *testing.T) {
		result := env.mustRun("snapshot", "list", inst.name)

		// Verify snapshot appears in list
		if !strings.Contains(result.Stdout, snapshotName) {
			t.Errorf("Snapshot %s not found in list output: %s", snapshotName, result.Stdout)
		}

		// Verify headers are present
		if !strings.Contains(result.Stdout, "NAME") {
			t.Error("List output should contain NAME header")
		}
		if !strings.Contains(result.Stdout, "CREATED") {
			t.Error("List output should contain CREATED header")
		}
	})

	t.Run("revert", func(t *testing.T) {
		// Start the instance
		inst.start()
		if !inst.waitForRunning(60 * time.Second) {
			t.Fatal("Instance did not start")
		}
		if !inst.waitForSSH(120 * time.Second) {
			inst.dumpDiagnostics()
			t.Fatal("SSH did not become available")
		}

		// Create a marker file
		markerResult := inst.ssh("touch", "/tmp/test-marker-file")
		if !markerResult.Success() {
			t.Fatalf("Failed to create marker file: %v", markerResult.Stderr)
		}

		// Verify marker exists
		checkResult := inst.ssh("ls", "/tmp/test-marker-file")
		if !checkResult.Success() {
			t.Fatal("Marker file should exist before revert")
		}

		// Stop instance for revert
		inst.forceStop()

		// Revert to snapshot
		result := env.mustRun("snapshot", "revert", inst.name, snapshotName, "--force")
		if !strings.Contains(result.Stdout, "reverted to snapshot") {
			t.Errorf("Expected revert message, got: %s", result.Stdout)
		}

		// Start instance again
		inst.start()
		if !inst.waitForRunning(60 * time.Second) {
			t.Fatal("Instance did not start after revert")
		}
		if !inst.waitForSSH(120 * time.Second) {
			t.Fatal("SSH did not become available after revert")
		}

		// Verify marker file is gone (reverted state)
		checkResult = inst.ssh("ls", "/tmp/test-marker-file")
		if checkResult.Success() {
			t.Error("Marker file should not exist after revert")
		}

		// Stop for remaining tests
		inst.forceStop()
	})

	t.Run("remove", func(t *testing.T) {
		result := env.mustRun("snapshot", "remove", inst.name, snapshotName, "--force")
		if !strings.Contains(result.Stdout, "removed") {
			t.Errorf("Expected removal message, got: %s", result.Stdout)
		}

		// Verify snapshot is gone
		listResult := env.mustRun("snapshot", "list", inst.name)
		if strings.Contains(listResult.Stdout, snapshotName) {
			t.Error("Snapshot should not appear in list after removal")
		}
	})

	t.Run("requires-stopped", func(t *testing.T) {
		// Start instance
		inst.start()
		if !inst.waitForRunning(60 * time.Second) {
			t.Fatal("Instance did not start")
		}
		defer inst.forceStop()

		// Snapshot create should fail when running
		result := env.run("snapshot", "create", inst.name, "should-fail")
		if result.Success() {
			t.Error("Snapshot create should fail when instance is running")
		}
		if !strings.Contains(result.Stderr, "must be stopped") && !strings.Contains(result.Stdout, "must be stopped") {
			t.Errorf("Expected 'must be stopped' error, got: %s %s", result.Stdout, result.Stderr)
		}

		// Create a snapshot while stopped for revert test
		inst.forceStop()
		env.mustRun("snapshot", "create", inst.name, "temp-snap")

		// Start again
		inst.start()
		if !inst.waitForRunning(60 * time.Second) {
			t.Fatal("Instance did not restart")
		}

		// Snapshot revert should fail when running
		result = env.run("snapshot", "revert", inst.name, "temp-snap", "--force")
		if result.Success() {
			t.Error("Snapshot revert should fail when instance is running")
		}
		if !strings.Contains(result.Stderr, "must be stopped") && !strings.Contains(result.Stdout, "must be stopped") {
			t.Errorf("Expected 'must be stopped' error, got: %s %s", result.Stdout, result.Stderr)
		}

		// Cleanup temp snapshot
		inst.forceStop()
		env.run("snapshot", "remove", inst.name, "temp-snap", "--force")
	})
}
