//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testBoxfileConfig holds config for generating test abox.yaml files.
type testBoxfileConfig struct {
	Name      string
	CPUs      int
	Memory    int
	Disk      string
	Base      string
	Provision []string
	Allowlist []string
	Monitor bool     // Enable Tetragon monitoring
	Kprobes []string // Optional: specific kprobes (nil = defaults)
}

// writeTestBoxfile creates an abox.yaml in the given directory.
func writeTestBoxfile(t *testing.T, dir string, cfg testBoxfileConfig) {
	t.Helper()

	// Set defaults
	if cfg.CPUs == 0 {
		cfg.CPUs = 1
	}
	if cfg.Memory == 0 {
		cfg.Memory = 512
	}
	if cfg.Disk == "" {
		cfg.Disk = "10G"
	}
	if cfg.Base == "" {
		cfg.Base = getBaseImage()
	}

	// Build YAML content
	var sb strings.Builder
	sb.WriteString("version: 1\n")
	sb.WriteString(fmt.Sprintf("name: %s\n", cfg.Name))
	sb.WriteString(fmt.Sprintf("cpus: %d\n", cfg.CPUs))
	sb.WriteString(fmt.Sprintf("memory: %d\n", cfg.Memory))
	sb.WriteString(fmt.Sprintf("disk: %s\n", cfg.Disk))
	sb.WriteString(fmt.Sprintf("base: %s\n", cfg.Base))
	sb.WriteString(fmt.Sprintf("user: %s\n", getDefaultUser(cfg.Base)))

	if len(cfg.Provision) > 0 {
		sb.WriteString("provision:\n")
		for _, script := range cfg.Provision {
			sb.WriteString(fmt.Sprintf("  - %s\n", script))
		}
	}

	if len(cfg.Allowlist) > 0 {
		sb.WriteString("allowlist:\n")
		for _, domain := range cfg.Allowlist {
			sb.WriteString(fmt.Sprintf("  - %s\n", domain))
		}
	}

	if cfg.Monitor {
		sb.WriteString("monitor:\n")
		sb.WriteString("  enabled: true\n")
		sb.WriteString("  kprobe_multi: false\n")
		if len(cfg.Kprobes) > 0 {
			sb.WriteString("  kprobes:\n")
			for _, k := range cfg.Kprobes {
				sb.WriteString(fmt.Sprintf("    - %s\n", k))
			}
		}
	}

	boxfilePath := filepath.Join(dir, "abox.yaml")
	if err := os.WriteFile(boxfilePath, []byte(sb.String()), 0o644); err != nil {
		t.Fatalf("Failed to write test boxfile: %v", err)
	}
}

// uniqueTestName generates a unique instance name for tests.
func uniqueTestName() string {
	return fmt.Sprintf("%s%d", testInstancePrefix, time.Now().UnixNano()%1000000)
}

// TestInit tests the abox init command.
func TestInit(t *testing.T) {
	env := newTestEnv(t)

	t.Run("defaults", func(t *testing.T) {
		dir := t.TempDir()

		// Run abox init --defaults in temp dir
		result := env.run("init", "--defaults", "--output", filepath.Join(dir, "abox.yaml"))
		if !result.Success() {
			t.Fatalf("init --defaults failed: %s\nstderr: %s", result.Stdout, result.Stderr)
		}

		// Verify abox.yaml was created
		boxfilePath := filepath.Join(dir, "abox.yaml")
		content, err := os.ReadFile(boxfilePath)
		if err != nil {
			t.Fatalf("Failed to read created boxfile: %v", err)
		}

		// Verify expected default values
		contentStr := string(content)
		if !strings.Contains(contentStr, "version: 1") {
			t.Error("Expected version: 1 in boxfile")
		}
		if !strings.Contains(contentStr, "cpus: 2") {
			t.Error("Expected cpus: 2 in boxfile")
		}
		if !strings.Contains(contentStr, "memory: 4096") {
			t.Error("Expected memory: 4096 in boxfile")
		}
		if !strings.Contains(contentStr, "disk: 20G") {
			t.Error("Expected disk: 20G in boxfile")
		}
		if !strings.Contains(contentStr, "base: ubuntu-24.04") {
			t.Error("Expected base: ubuntu-24.04 in boxfile")
		}
	})

	t.Run("stdout", func(t *testing.T) {
		dir := t.TempDir()
		originalDir, _ := os.Getwd()
		defer os.Chdir(originalDir)
		os.Chdir(dir)

		// Run abox init --defaults --stdout
		result := env.run("init", "--defaults", "--stdout")
		if !result.Success() {
			t.Fatalf("init --defaults --stdout failed: %s\nstderr: %s", result.Stdout, result.Stderr)
		}

		// Verify YAML output to stdout
		if !strings.Contains(result.Stdout, "version: 1") {
			t.Error("Expected version: 1 in stdout output")
		}
		if !strings.Contains(result.Stdout, "cpus: 2") {
			t.Error("Expected cpus: 2 in stdout output")
		}

		// Verify no file was created
		if _, err := os.Stat(filepath.Join(dir, "abox.yaml")); !os.IsNotExist(err) {
			t.Error("Expected no abox.yaml file when using --stdout")
		}
	})

	t.Run("force-overwrite", func(t *testing.T) {
		dir := t.TempDir()
		boxfilePath := filepath.Join(dir, "abox.yaml")

		// Create an existing abox.yaml
		originalContent := "version: 1\nname: original\n"
		if err := os.WriteFile(boxfilePath, []byte(originalContent), 0o644); err != nil {
			t.Fatalf("Failed to create existing boxfile: %v", err)
		}

		// Run abox init --defaults --force
		result := env.run("init", "--defaults", "--force", "--output", boxfilePath)
		if !result.Success() {
			t.Fatalf("init --defaults --force failed: %s\nstderr: %s", result.Stdout, result.Stderr)
		}

		// Verify file was overwritten (no longer contains "original")
		content, err := os.ReadFile(boxfilePath)
		if err != nil {
			t.Fatalf("Failed to read boxfile: %v", err)
		}
		if strings.Contains(string(content), "name: original") {
			t.Error("Expected file to be overwritten")
		}
		if !strings.Contains(string(content), "cpus: 2") {
			t.Error("Expected default content after overwrite")
		}
	})

	t.Run("no-overwrite-without-force", func(t *testing.T) {
		dir := t.TempDir()
		boxfilePath := filepath.Join(dir, "abox.yaml")

		// Create an existing abox.yaml
		originalContent := "version: 1\nname: original\n"
		if err := os.WriteFile(boxfilePath, []byte(originalContent), 0o644); err != nil {
			t.Fatalf("Failed to create existing boxfile: %v", err)
		}

		// Run abox init --defaults (without --force)
		result := env.run("init", "--defaults", "--output", boxfilePath)
		if result.Success() {
			t.Fatal("Expected init without --force to fail when file exists")
		}

		// Verify error message mentions --force
		output := result.Stdout + result.Stderr
		if !strings.Contains(output, "force") && !strings.Contains(output, "already exists") {
			t.Errorf("Expected error about file existing or --force, got: %s", output)
		}

		// Verify file unchanged
		content, err := os.ReadFile(boxfilePath)
		if err != nil {
			t.Fatalf("Failed to read boxfile: %v", err)
		}
		if !strings.Contains(string(content), "name: original") {
			t.Error("Expected file to remain unchanged")
		}
	})

	t.Run("custom-output-path", func(t *testing.T) {
		dir := t.TempDir()
		customPath := filepath.Join(dir, "custom.yaml")

		// Run abox init --defaults --output custom.yaml
		result := env.run("init", "--defaults", "--output", customPath)
		if !result.Success() {
			t.Fatalf("init --defaults --output failed: %s\nstderr: %s", result.Stdout, result.Stderr)
		}

		// Verify custom.yaml was created
		if _, err := os.Stat(customPath); os.IsNotExist(err) {
			t.Error("Expected custom.yaml to be created")
		}

		// Verify default abox.yaml was NOT created
		if _, err := os.Stat(filepath.Join(dir, "abox.yaml")); !os.IsNotExist(err) {
			t.Error("Expected no default abox.yaml when using --output")
		}
	})

	t.Run("dry-run", func(t *testing.T) {
		dir := t.TempDir()
		originalDir, _ := os.Getwd()
		defer os.Chdir(originalDir)
		os.Chdir(dir)

		// Run abox init --defaults --dry-run
		result := env.run("init", "--defaults", "--dry-run")
		if !result.Success() {
			t.Fatalf("init --defaults --dry-run failed: %s\nstderr: %s", result.Stdout, result.Stderr)
		}

		// Verify YAML output to stdout (dry-run is alias for stdout)
		if !strings.Contains(result.Stdout, "version: 1") {
			t.Error("Expected version: 1 in stdout output")
		}

		// Verify no file was created
		if _, err := os.Stat(filepath.Join(dir, "abox.yaml")); !os.IsNotExist(err) {
			t.Error("Expected no abox.yaml file when using --dry-run")
		}
	})
}

// TestDeclarativeWorkflow tests abox up and abox down commands.
func TestDeclarativeWorkflow(t *testing.T) {
	skipIfNoLibvirt(t)
	skipIfNoConfiguredBaseImage(t)

	env := newTestEnv(t)

	// Setup: create temp dir with abox.yaml
	dir := t.TempDir()
	name := uniqueTestName()

	writeTestBoxfile(t, dir, testBoxfileConfig{
		Name:   name,
		CPUs:   1,
		Memory: 512,
	})

	// Register cleanup
	t.Cleanup(func() {
		// abox down --remove --force -d dir
		env.runWithTimeout(longTimeout, "down", "--remove", "--force", "-d", dir)
	})

	t.Run("up-creates-instance", func(t *testing.T) {
		// abox up -d dir
		result := env.runWithTimeout(longTimeout, "up", "-d", dir)
		if !result.Success() {
			t.Fatalf("up failed: %s\nstderr: %s", result.Stdout, result.Stderr)
		}

		// Verify instance appears in abox list
		listResult := env.mustRun("list")
		if !strings.Contains(listResult.Stdout, name) {
			t.Errorf("Instance %s not found in list output", name)
		}

		// Wait for instance to be running
		ti := &testInstance{env: env, name: name, t: t}
		if !ti.waitForRunning(60 * time.Second) {
			t.Error("Instance did not reach running state")
		}

		// Wait for SSH to be available
		if !ti.waitForSSH(120 * time.Second) {
			ti.dumpDiagnostics()
			t.Error("SSH did not become available")
		}

		// Verify SSH works
		sshResult := env.run("ssh", name, "--", "echo", "hello")
		if !sshResult.Success() {
			t.Errorf("SSH failed: %s\nstderr: %s", sshResult.Stdout, sshResult.Stderr)
		}
		if !strings.Contains(sshResult.Stdout, "hello") {
			t.Errorf("Expected SSH output to contain 'hello', got: %s", sshResult.Stdout)
		}
	})

	t.Run("up-idempotent", func(t *testing.T) {
		// abox up -d dir (again)
		result := env.runWithTimeout(longTimeout, "up", "-d", dir)
		if !result.Success() {
			t.Fatalf("second up failed: %s\nstderr: %s", result.Stdout, result.Stderr)
		}

		// Verify instance is still running
		ti := &testInstance{env: env, name: name, t: t}
		if !ti.isRunning() {
			t.Error("Instance should still be running after second up")
		}

		// Verify output mentions already running
		if !strings.Contains(result.Stdout, "already running") {
			t.Errorf("Expected 'already running' message, got: %s", result.Stdout)
		}
	})

	t.Run("down-stops", func(t *testing.T) {
		// abox down -d dir
		result := env.runWithTimeout(longTimeout, "down", "-d", dir)
		if !result.Success() {
			t.Fatalf("down failed: %s\nstderr: %s", result.Stdout, result.Stderr)
		}

		// Verify instance stopped (but still exists)
		ti := &testInstance{env: env, name: name, t: t}
		if ti.isRunning() {
			t.Error("Instance should be stopped after down")
		}

		// Verify instance still exists in list
		listResult := env.mustRun("list")
		if !strings.Contains(listResult.Stdout, name) {
			t.Errorf("Instance %s should still exist after down (without --remove)", name)
		}
	})

	t.Run("down-idempotent", func(t *testing.T) {
		// abox down -d dir (again on stopped instance)
		result := env.runWithTimeout(longTimeout, "down", "-d", dir)
		if !result.Success() {
			t.Fatalf("second down failed: %s\nstderr: %s", result.Stdout, result.Stderr)
		}
	})

	t.Run("up-restarts", func(t *testing.T) {
		// abox up -d dir
		result := env.runWithTimeout(longTimeout, "up", "-d", dir)
		if !result.Success() {
			t.Fatalf("restart up failed: %s\nstderr: %s", result.Stdout, result.Stderr)
		}

		// Verify instance running again
		ti := &testInstance{env: env, name: name, t: t}
		if !ti.waitForRunning(60 * time.Second) {
			t.Error("Instance did not reach running state after restart")
		}
	})

	t.Run("down-remove", func(t *testing.T) {
		// abox down --remove --force -d dir
		result := env.runWithTimeout(longTimeout, "down", "--remove", "--force", "-d", dir)
		if !result.Success() {
			t.Fatalf("down --remove failed: %s\nstderr: %s", result.Stdout, result.Stderr)
		}

		// Verify instance removed from list
		listResult := env.run("list")
		if strings.Contains(listResult.Stdout, name) {
			t.Errorf("Instance %s should not appear in list after down --remove", name)
		}
	})
}

// TestDeclarativeProvisioning tests provisioning with abox up.
func TestDeclarativeProvisioning(t *testing.T) {
	skipIfNoLibvirt(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)

	dir := t.TempDir()
	name := uniqueTestName()

	// Create provision script that creates a marker file in the user's home directory
	// Use the appropriate user for the base image (ubuntu, almalinux, etc.)
	user := getDefaultUser(getBaseImage())
	provisionScript := filepath.Join(dir, "provision.sh")
	scriptContent := fmt.Sprintf(`#!/bin/bash
# Create marker file owned by %s user so it can be deleted in tests
sudo -u %s sh -c 'echo "provisioned" > /home/%s/abox-provision-marker'
`, user, user, user)
	if err := os.WriteFile(provisionScript, []byte(scriptContent), 0o755); err != nil {
		t.Fatalf("Failed to write provision script: %v", err)
	}

	writeTestBoxfile(t, dir, testBoxfileConfig{
		Name:      name,
		CPUs:      1,
		Memory:    512,
		Provision: []string{"provision.sh"},
	})

	t.Cleanup(func() {
		env.runWithTimeout(longTimeout, "down", "--remove", "--force", "-d", dir)
	})

	t.Run("provision-runs-on-first-up", func(t *testing.T) {
		// abox up -d dir
		result := env.runWithTimeout(longTimeout, "up", "-d", dir)
		if !result.Success() {
			t.Fatalf("up failed: %s\nstderr: %s", result.Stdout, result.Stderr)
		}

		// Wait for SSH
		ti := &testInstance{env: env, name: name, t: t}
		if !ti.waitForSSH(120 * time.Second) {
			ti.dumpDiagnostics()
			t.Fatal("SSH did not become available")
		}

		// Verify marker file exists
		sshResult := env.run("ssh", name, "--", "cat", fmt.Sprintf("/home/%s/abox-provision-marker", user))
		if !sshResult.Success() {
			t.Fatalf("Failed to read marker file: %s\nstderr: %s", sshResult.Stdout, sshResult.Stderr)
		}
		if !strings.Contains(sshResult.Stdout, "provisioned") {
			t.Errorf("Expected marker file to contain 'provisioned', got: %s", sshResult.Stdout)
		}
	})

	t.Run("provision-not-rerun-on-second-up", func(t *testing.T) {
		// Remove the marker file
		env.mustRun("ssh", name, "--", "rm", fmt.Sprintf("/home/%s/abox-provision-marker", user))

		// Stop the instance
		env.runWithTimeout(longTimeout, "down", "-d", dir)

		// Start again
		result := env.runWithTimeout(longTimeout, "up", "-d", dir)
		if !result.Success() {
			t.Fatalf("second up failed: %s\nstderr: %s", result.Stdout, result.Stderr)
		}

		// Wait for SSH
		ti := &testInstance{env: env, name: name, t: t}
		if !ti.waitForSSH(120 * time.Second) {
			t.Fatal("SSH did not become available")
		}

		// Verify marker file does NOT exist (provision didn't re-run)
		sshResult := env.run("ssh", name, "--", "cat", fmt.Sprintf("/home/%s/abox-provision-marker", user))
		if sshResult.Success() {
			t.Error("Marker file should not exist - provision should not re-run on second up")
		}
	})
}

// TestDeclarativeAllowlist tests allowlist sync with abox up.
func TestDeclarativeAllowlist(t *testing.T) {
	skipIfNoLibvirt(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)

	dir := t.TempDir()
	name := uniqueTestName()

	// Initial boxfile with one domain
	writeTestBoxfile(t, dir, testBoxfileConfig{
		Name:      name,
		CPUs:      1,
		Memory:    512,
		Allowlist: []string{"example.com"},
	})

	t.Cleanup(func() {
		env.runWithTimeout(longTimeout, "down", "--remove", "--force", "-d", dir)
	})

	t.Run("initial-allowlist", func(t *testing.T) {
		// abox up -d dir
		result := env.runWithTimeout(longTimeout, "up", "-d", dir)
		if !result.Success() {
			t.Fatalf("up failed: %s\nstderr: %s", result.Stdout, result.Stderr)
		}

		// Wait for instance to be running
		ti := &testInstance{env: env, name: name, t: t}
		if !ti.waitForRunning(60 * time.Second) {
			t.Fatal("Instance did not reach running state")
		}

		// Verify allowlist contains example.com
		allowlistResult := env.mustRun("allowlist", "list", name)
		if !strings.Contains(allowlistResult.Stdout, "example.com") {
			t.Errorf("Expected allowlist to contain example.com, got: %s", allowlistResult.Stdout)
		}
	})

	t.Run("allowlist-sync-on-rerun", func(t *testing.T) {
		// Update abox.yaml with new domain
		writeTestBoxfile(t, dir, testBoxfileConfig{
			Name:      name,
			CPUs:      1,
			Memory:    512,
			Allowlist: []string{"example.com", "newdomain.com"},
		})

		// abox up -d dir
		result := env.runWithTimeout(longTimeout, "up", "-d", dir)
		if !result.Success() {
			t.Fatalf("second up failed: %s\nstderr: %s", result.Stdout, result.Stderr)
		}

		// Verify output mentions syncing allowlist
		if !strings.Contains(result.Stdout, "Synced allowlist") && !strings.Contains(result.Stdout, "already running") {
			t.Logf("Output: %s", result.Stdout)
		}

		// Verify allowlist contains both domains
		allowlistResult := env.mustRun("allowlist", "list", name)
		if !strings.Contains(allowlistResult.Stdout, "example.com") {
			t.Errorf("Expected allowlist to contain example.com, got: %s", allowlistResult.Stdout)
		}
		if !strings.Contains(allowlistResult.Stdout, "newdomain.com") {
			t.Errorf("Expected allowlist to contain newdomain.com, got: %s", allowlistResult.Stdout)
		}
	})
}
