//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestExportImport tests the export and import cycle.
func TestExportImport(t *testing.T) {
	skipIfBackendUnavailable(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()

	// Captured before export: the archive carries this networking config, and a
	// later import must NOT reuse it (the original instance still owns it).
	archivedIP := inst.configValue("ip_address")

	// Create a temp directory for the export
	tempDir, err := os.MkdirTemp("", "abox-e2e-export-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	archivePath := filepath.Join(tempDir, inst.name+".abox.tar.gz")

	t.Run("export", func(t *testing.T) {
		env, inst := env.sub(t), inst.sub(t)
		// Instance must be stopped to export
		result := env.mustRunWithTimeout(longTimeout, "export", inst.name, archivePath)
		if !strings.Contains(result.Stdout, "Archive size:") {
			t.Errorf("Expected archive size message, got: %s", result.Stdout)
		}

		// Verify archive exists
		if _, err := os.Stat(archivePath); os.IsNotExist(err) {
			t.Error("Archive file should exist after export")
		}
	})

	// Create a new instance for import
	importedInst := env.newTestInstance()

	t.Run("import", func(t *testing.T) {
		env, importedInst := env.sub(t), importedInst.sub(t)
		result := env.mustRunWithTimeout(longTimeout, "import", archivePath, importedInst.name)
		if !strings.Contains(result.Stdout, "imported successfully") {
			t.Errorf("Expected import success message, got: %s", result.Stdout)
		}

		// Verify imported instance appears in list
		listResult := env.mustRun("list")
		if !strings.Contains(listResult.Stdout, importedInst.name) {
			t.Errorf("Imported instance %s not found in list", importedInst.name)
		}

		// Regression: import must allocate fresh networking rather than reuse the
		// archived subnet/IP — the original instance still owns those here, so a
		// reuse would collide.
		importedIP := importedInst.configValue("ip_address")
		if importedIP == archivedIP {
			t.Errorf("Imported instance reused the archived IP %s; import must allocate fresh networking", archivedIP)
		}

		// Start the imported instance to verify it works. waitForSSH probes via
		// `abox ssh`, which targets the newly allocated IP — reachability proves the
		// first start re-rendered the guest's static IP from regenerated cloud-init.
		importedInst.start()
		if !importedInst.waitForRunning(60 * time.Second) {
			t.Fatal("Imported instance did not start")
		}
		if !importedInst.waitForSSH(120 * time.Second) {
			t.Fatal("SSH did not become available on imported instance at its newly allocated IP")
		}

		// Simple verification - run a command
		sshResult := importedInst.ssh("echo", "imported-ok")
		if !sshResult.Success() || !strings.Contains(sshResult.Stdout, "imported-ok") {
			t.Error("Failed to run command on imported instance")
		}

		// The guest itself must hold the newly allocated address, not the archived one.
		ipResult := importedInst.ssh("hostname", "-I")
		if !ipResult.Success() || !strings.Contains(ipResult.Stdout, importedIP) {
			t.Errorf("Imported guest should hold the newly allocated IP %s, got: %s", importedIP, ipResult.Stdout)
		}

		importedInst.forceStop()
	})

	t.Run("import-overrides", func(t *testing.T) {
		env := env.sub(t)
		overrideInst := env.newTestInstance()

		result := env.mustRunWithTimeout(longTimeout, "import", archivePath, overrideInst.name, "--cpus", "2", "--memory", "1024")
		if !result.Success() {
			t.Fatalf("Import with overrides failed: %v", result.Err)
		}

		// Verify the overrides were applied
		configResult := env.mustRun("config", "view", overrideInst.name)
		if !strings.Contains(configResult.Stdout, "cpus: 2") {
			t.Error("Expected cpus: 2 in config")
		}
		if !strings.Contains(configResult.Stdout, "memory: 1024") {
			t.Error("Expected memory: 1024 in config")
		}
	})

	t.Run("requires-stopped", func(t *testing.T) {
		env, inst := env.sub(t), inst.sub(t)
		// Start the original instance
		inst.start()
		if !inst.waitForRunning(60 * time.Second) {
			t.Fatal("Instance did not start")
		}
		defer inst.forceStop()

		// Export should fail when running
		result := env.run("export", inst.name, filepath.Join(tempDir, "should-fail.tar.gz"))
		if result.Success() {
			t.Error("Export should fail when instance is running")
		}
		if !strings.Contains(result.Stderr, "running") && !strings.Contains(result.Stdout, "running") {
			t.Errorf("Expected error about running instance, got: %s %s", result.Stdout, result.Stderr)
		}
	})
}
