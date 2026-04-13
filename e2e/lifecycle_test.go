//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// TestInstanceLifecycle tests the full create -> start -> stop -> remove cycle.
func TestInstanceLifecycle(t *testing.T) {
	skipIfNoLibvirt(t)
	skipIfNoConfiguredBaseImage(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()

	// Test create
	t.Run("create", func(t *testing.T) {
		inst.create()

		// Verify instance appears in list
		result := env.mustRun("list")
		if !strings.Contains(result.Stdout, inst.name) {
			t.Errorf("Instance %s not found in list output", inst.name)
		}
	})

	// Test start
	t.Run("start", func(t *testing.T) {
		inst.start()

		// Wait for instance to be running
		if !inst.waitForRunning(60 * 1000000000) { // 60 seconds
			t.Fatal("Instance did not reach running state")
		}

		// Verify status shows running
		status := inst.status()
		if !vmStatePattern.MatchString(status) {
			t.Errorf("Expected VM state to be running, got: %s", status)
		}
	})

	// Test stop
	t.Run("stop", func(t *testing.T) {
		inst.forceStop()

		// Verify instance is stopped - use regex to match "State: running"
		// to avoid matching "not running" from DNS/HTTP filter status
		status := inst.status()
		if vmStatePattern.MatchString(status) {
			t.Errorf("Instance should not be running after stop, status: %s", status)
		}
	})

	// Test remove
	t.Run("remove", func(t *testing.T) {
		inst.remove()

		// Verify instance no longer appears in list
		result := env.run("list")
		if strings.Contains(result.Stdout, inst.name) {
			t.Errorf("Instance %s should not appear in list after remove", inst.name)
		}
	})
}

// TestCreateWithOptions tests instance creation with various options.
func TestCreateWithOptions(t *testing.T) {
	skipIfNoLibvirt(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)

	t.Run("custom-resources", func(t *testing.T) {
		inst := env.newTestInstance()
		inst.createWithArgs("--cpus", "2", "--memory", "1024", "--disk", "10G", "--base", getBaseImage())

		result := env.mustRun("config", "view", inst.name)
		if !strings.Contains(result.Stdout, "cpus: 2") {
			t.Error("Expected cpus: 2 in config")
		}
		if !strings.Contains(result.Stdout, "memory: 1024") {
			t.Error("Expected memory: 1024 in config")
		}
	})

	t.Run("dry-run", func(t *testing.T) {
		// Dry run should not create the instance
		name := "e2edryrun"
		result := env.run("create", name, "--dry-run")

		if !result.Success() {
			t.Fatalf("Dry run failed: %v", result.Err)
		}

		// Instance should not exist
		listResult := env.run("list")
		if strings.Contains(listResult.Stdout, name) {
			t.Error("Dry run should not create instance")
		}
	})
}

// TestStatusCommand tests the status command output.
func TestStatusCommand(t *testing.T) {
	skipIfNoLibvirt(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()

	t.Run("stopped-instance", func(t *testing.T) {
		status := inst.status()

		// Should show instance info even when stopped
		if !strings.Contains(status, inst.name) {
			t.Error("Status should contain instance name")
		}
	})

	t.Run("running-instance", func(t *testing.T) {
		inst.start()
		defer inst.forceStop()

		if !inst.waitForRunning(60 * 1000000000) {
			t.Fatal("Instance did not start")
		}

		status := inst.status()
		if !vmStatePattern.MatchString(status) {
			t.Error("Status should show VM state as running")
		}
	})
}

// TestListCommand tests the list command.
func TestListCommand(t *testing.T) {
	skipIfNoLibvirt(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)

	t.Run("empty-list", func(t *testing.T) {
		// This test assumes no other e2e test instances exist
		// We can't guarantee this, so just check the command runs
		result := env.run("list")
		if !result.Success() {
			t.Errorf("List command failed: %v", result.Err)
		}
	})

	t.Run("with-instances", func(t *testing.T) {
		inst := env.newTestInstance()
		inst.create()

		result := env.mustRun("list")

		// Check header
		if !strings.Contains(result.Stdout, "NAME") {
			t.Error("List should contain NAME header")
		}

		// Check instance appears
		if !strings.Contains(result.Stdout, inst.name) {
			t.Errorf("List should contain instance %s", inst.name)
		}
	})
}

// TestRemoveConfirmation tests that remove requires confirmation.
func TestRemoveConfirmation(t *testing.T) {
	skipIfNoLibvirt(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()

	// Without --force, remove should fail (no TTY for confirmation)
	result := env.run("remove", inst.name)
	if result.Success() {
		t.Error("Remove without --force should fail without TTY")
	}

	// With --force, remove should succeed
	result = env.run("remove", "--force", inst.name)
	if !result.Success() {
		t.Errorf("Remove with --force failed: %v", result.Err)
	}
}
