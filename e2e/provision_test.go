//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestProvision tests the provision command.
func TestProvision(t *testing.T) {
	skipIfNoLibvirt(t)
	skipIfNoConfiguredBaseImage(t)
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

	// Create temp directory for test scripts
	tempDir, err := os.MkdirTemp("", "abox-e2e-provision-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	t.Run("basic", func(t *testing.T) {
		// Create a simple provision script that creates a marker file
		scriptPath := filepath.Join(tempDir, "basic.sh")
		script := `#!/bin/bash
touch /tmp/provision-marker
echo "Provision script executed"
`
		if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
			t.Fatalf("Failed to write script: %v", err)
		}

		result := env.mustRun("provision", inst.name, "-s", scriptPath)
		if !strings.Contains(result.Stdout, "Provision completed successfully") {
			t.Errorf("Expected success message, got: %s", result.Stdout)
		}

		// Verify the marker file was created
		checkResult := inst.ssh("ls", "/tmp/provision-marker")
		if !checkResult.Success() {
			t.Error("Provision script should have created marker file")
		}
	})

	t.Run("env-vars", func(t *testing.T) {
		// Create a script that outputs environment variables
		scriptPath := filepath.Join(tempDir, "env-vars.sh")
		script := `#!/bin/bash
echo "ABOX_NAME=$ABOX_NAME"
echo "ABOX_USER=$ABOX_USER"
echo "ABOX_IP=$ABOX_IP"
echo "ABOX_GATEWAY=$ABOX_GATEWAY"
echo "ABOX_SUBNET=$ABOX_SUBNET"
`
		if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
			t.Fatalf("Failed to write script: %v", err)
		}

		result := env.mustRun("provision", inst.name, "-s", scriptPath)

		// Verify environment variables were set
		if !strings.Contains(result.Stdout, "ABOX_NAME="+inst.name) {
			t.Errorf("Expected ABOX_NAME=%s, got: %s", inst.name, result.Stdout)
		}
		expectedUser := getDefaultUser(getBaseImage())
		if !strings.Contains(result.Stdout, "ABOX_USER="+expectedUser) {
			t.Errorf("Expected ABOX_USER=%s, got: %s", expectedUser, result.Stdout)
		}
		if !strings.Contains(result.Stdout, "ABOX_IP=") {
			t.Error("Expected ABOX_IP to be set")
		}
		if !strings.Contains(result.Stdout, "ABOX_GATEWAY=") {
			t.Error("Expected ABOX_GATEWAY to be set")
		}
		if !strings.Contains(result.Stdout, "ABOX_SUBNET=") {
			t.Error("Expected ABOX_SUBNET to be set")
		}
	})

	t.Run("overlay", func(t *testing.T) {
		// Create an overlay directory with a test file
		overlayDir := filepath.Join(tempDir, "overlay")
		if err := os.MkdirAll(overlayDir, 0o755); err != nil {
			t.Fatalf("Failed to create overlay dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(overlayDir, "overlay-file.txt"), []byte("overlay content"), 0o644); err != nil {
			t.Fatalf("Failed to write overlay file: %v", err)
		}

		// Create a script that reads from the overlay
		scriptPath := filepath.Join(tempDir, "overlay.sh")
		script := `#!/bin/bash
if [ -f /tmp/abox/overlay/overlay-file.txt ]; then
    echo "OVERLAY_CONTENT=$(cat /tmp/abox/overlay/overlay-file.txt)"
else
    echo "ERROR: overlay file not found"
    exit 1
fi
`
		if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
			t.Fatalf("Failed to write script: %v", err)
		}

		result := env.mustRun("provision", inst.name, "-s", scriptPath, "--overlay", overlayDir)
		if !strings.Contains(result.Stdout, "OVERLAY_CONTENT=overlay content") {
			t.Errorf("Expected overlay content to be read, got: %s", result.Stdout)
		}
	})

	t.Run("requires-running", func(t *testing.T) {
		// Stop the instance
		inst.forceStop()

		scriptPath := filepath.Join(tempDir, "basic.sh")
		result := env.run("provision", inst.name, "-s", scriptPath)
		if result.Success() {
			t.Error("Provision should fail when instance is not running")
		}
		// The error message should indicate the instance is not running
		output := result.Stdout + result.Stderr
		if !strings.Contains(output, "not running") && !strings.Contains(output, "must be running") {
			t.Errorf("Expected error about instance not running, got: %s", output)
		}
	})
}
