//go:build e2e

// Package e2e provides end-to-end tests for the abox CLI.
//
// These tests require:
// - libvirt/qemu installed and running
// - sudo/pkexec available for privilege escalation
// - Downloaded base images (run `abox base pull ubuntu-24.04` first)
//
// Run with: go test -tags=e2e -v ./e2e/...
//
// Environment variables:
//   - ABOX_E2E_BASE: Override the base image (default: ubuntu-24.04)
//     Example: ABOX_E2E_BASE=almalinux-9 go test -tags=e2e -v ./e2e/...
package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sandialabs/abox/internal/config"
)

const (
	// defaultTimeout is the default timeout for abox commands
	defaultTimeout = 2 * time.Minute

	// longTimeout is for commands that may take longer (create, start)
	longTimeout = 5 * time.Minute

	// testInstancePrefix is used to identify test instances
	testInstancePrefix = "e2etest"

	// defaultBaseImage is the default base image for e2e tests
	defaultBaseImage = "ubuntu-24.04"
)

// getBaseImage returns the base image to use for e2e tests.
// Override with ABOX_E2E_BASE environment variable.
func getBaseImage() string {
	if base := os.Getenv("ABOX_E2E_BASE"); base != "" {
		return base
	}
	return defaultBaseImage
}

// getDefaultUser returns the default SSH user for a base image.
func getDefaultUser(base string) string {
	return config.DefaultUserForBase(base)
}

// testEnv holds environment configuration for e2e tests.
type testEnv struct {
	aboxBinary string
	t          *testing.T
}

// newTestEnv creates a new test environment.
// It ensures the abox binary exists and is executable.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	// Find abox binary - prefer the one in the repo root
	candidates := []string{
		"./abox",
		"../abox",
		filepath.Join(os.Getenv("HOME"), ".local/bin/abox"),
	}

	var aboxPath string
	for _, candidate := range candidates {
		absPath, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		if info, err := os.Stat(absPath); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			aboxPath = absPath
			break
		}
	}

	if aboxPath == "" {
		t.Skip("abox binary not found - run 'go build -o abox ./cmd/abox' first")
	}

	return &testEnv{
		aboxBinary: aboxPath,
		t:          t,
	}
}

// runResult holds the result of running an abox command.
type runResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// Success returns true if the command succeeded (exit code 0).
func (r *runResult) Success() bool {
	return r.ExitCode == 0 && r.Err == nil
}

// run executes an abox command and returns the result.
func (e *testEnv) run(args ...string) *runResult {
	return e.runWithTimeout(defaultTimeout, args...)
}

// runWithTimeout executes an abox command with a custom timeout.
func (e *testEnv) runWithTimeout(timeout time.Duration, args ...string) *runResult {
	e.t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, e.aboxBinary, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	e.t.Logf("Running: %s %s", e.aboxBinary, strings.Join(args, " "))

	err := cmd.Run()

	result := &runResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
		Err:    err,
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
	}

	// Only log stderr (stdout is too verbose)
	if result.Stderr != "" {
		e.t.Logf("stderr:\n%s", result.Stderr)
	}

	return result
}

// mustRun executes an abox command and fails the test if it doesn't succeed.
func (e *testEnv) mustRun(args ...string) *runResult {
	e.t.Helper()
	result := e.run(args...)
	if !result.Success() {
		e.t.Fatalf("Command failed: %s %s\nstdout: %s\nstderr: %s\nerror: %v",
			e.aboxBinary, strings.Join(args, " "), result.Stdout, result.Stderr, result.Err)
	}
	return result
}

// mustRunWithTimeout executes an abox command with a custom timeout and fails if it doesn't succeed.
func (e *testEnv) mustRunWithTimeout(timeout time.Duration, args ...string) *runResult {
	e.t.Helper()
	result := e.runWithTimeout(timeout, args...)
	if !result.Success() {
		e.t.Fatalf("Command failed: %s %s\nstdout: %s\nstderr: %s\nerror: %v",
			e.aboxBinary, strings.Join(args, " "), result.Stdout, result.Stderr, result.Err)
	}
	return result
}

// testInstance represents a test instance with cleanup.
type testInstance struct {
	env  *testEnv
	name string
	t    *testing.T
}

// newTestInstance creates a unique test instance name and registers cleanup.
func (e *testEnv) newTestInstance() *testInstance {
	e.t.Helper()

	name := fmt.Sprintf("%s%d", testInstancePrefix, time.Now().UnixNano()%1000000)

	ti := &testInstance{
		env:  e,
		name: name,
		t:    e.t,
	}

	// Register cleanup to remove the instance
	e.t.Cleanup(func() {
		ti.cleanup()
	})

	return ti
}

// cleanup removes the test instance if it exists.
func (ti *testInstance) cleanup() {
	// Unmount any SSHFS mounts first (ignore errors)
	ti.env.run("unmount", ti.name)

	// Stop the instance first (ignore errors, may not be running)
	ti.env.run("stop", "--force", ti.name)

	// Remove the instance (ignore errors, may not exist)
	result := ti.env.run("remove", "--force", ti.name)

	if result.Success() {
		ti.t.Logf("Cleaned up test instance: %s", ti.name)
	}
}

// create creates the test instance with default settings.
func (ti *testInstance) create() {
	ti.t.Helper()
	ti.env.mustRunWithTimeout(longTimeout, "create", ti.name, "--cpus", "1", "--memory", "512", "--base", getBaseImage())
}

// createWithArgs creates the test instance with custom arguments.
func (ti *testInstance) createWithArgs(args ...string) {
	ti.t.Helper()
	allArgs := append([]string{"create", ti.name}, args...)
	ti.env.mustRunWithTimeout(longTimeout, allArgs...)
}

// start starts the test instance.
func (ti *testInstance) start() {
	ti.t.Helper()
	ti.env.mustRunWithTimeout(longTimeout, "start", ti.name)
}

// stop stops the test instance.
func (ti *testInstance) stop() {
	ti.t.Helper()
	ti.env.mustRun("stop", ti.name)
}

// forceStop force-stops the test instance.
func (ti *testInstance) forceStop() {
	ti.t.Helper()
	ti.env.mustRun("stop", "--force", ti.name)
}

// remove removes the test instance.
func (ti *testInstance) remove() {
	ti.t.Helper()
	ti.env.mustRun("remove", "--force", ti.name)
}

// status returns the instance status output.
func (ti *testInstance) status() string {
	ti.t.Helper()
	result := ti.env.mustRun("status", ti.name)
	return result.Stdout
}

// vmStatePattern matches the VM state line with flexible whitespace
var vmStatePattern = regexp.MustCompile(`State:\s+running`)

// isRunning checks if the instance is in running state.
func (ti *testInstance) isRunning() bool {
	ti.t.Helper()
	result := ti.env.run("status", ti.name)
	// Use regex to match "State:" followed by whitespace and "running"
	// This avoids matching "not running" from DNS/HTTP filter status
	return vmStatePattern.MatchString(result.Stdout)
}

// waitForRunning waits for the instance to be in running state.
func (ti *testInstance) waitForRunning(timeout time.Duration) bool {
	ti.t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ti.isRunning() {
			return true
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

// waitForSSH waits for SSH to become available.
func (ti *testInstance) waitForSSH(timeout time.Duration) bool {
	ti.t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		result := ti.env.run("ssh", ti.name, "--", "echo", "ready")
		if result.Success() && strings.Contains(result.Stdout, "ready") {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

// waitForSSHCondition retries an SSH command until the condition function returns true or the timeout expires.
// Returns the last runResult. The condition receives the result of each attempt.
func (ti *testInstance) waitForSSHCondition(timeout time.Duration, interval time.Duration, condition func(*runResult) bool, command ...string) *runResult {
	ti.t.Helper()

	var result *runResult
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		result = ti.ssh(command...)
		if condition(result) {
			return result
		}
		time.Sleep(interval)
	}
	return result
}

// waitForCloudInit waits for cloud-init to complete all stages (including runcmd).
// SSH may become available before runcmd finishes, so tests that depend on runcmd
// (e.g., CA cert trust store updates, Tetragon installation) should call this first.
func (ti *testInstance) waitForCloudInit() {
	ti.t.Helper()
	ti.waitForSSHCondition(180*time.Second, 5*time.Second, func(r *runResult) bool {
		output := strings.TrimSpace(r.Stdout)
		return strings.Contains(output, "done") || strings.Contains(output, "error")
	}, "cloud-init", "status")
}

// ssh runs a command via SSH and returns the result.
func (ti *testInstance) ssh(command ...string) *runResult {
	ti.t.Helper()
	args := append([]string{"ssh", ti.name, "--"}, command...)
	return ti.env.run(args...)
}

// filterMode gets the current filter mode (active or passive).
func (ti *testInstance) filterMode() string {
	ti.t.Helper()
	result := ti.env.mustRun("net", "filter", ti.name)
	// Parse output for mode
	for _, line := range strings.Split(result.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "active") {
			return "active"
		}
		if strings.Contains(line, "passive") {
			return "passive"
		}
	}
	return ""
}

// setFilterMode sets the filter mode (active or passive).
func (ti *testInstance) setFilterMode(mode string) {
	ti.t.Helper()
	ti.env.mustRun("net", "filter", ti.name, mode)
}

// allowlistAdd adds a domain to the allowlist.
func (ti *testInstance) allowlistAdd(domain string) {
	ti.t.Helper()
	ti.env.mustRun("allowlist", "add", ti.name, domain)
}

// allowlistRemove removes a domain from the allowlist.
func (ti *testInstance) allowlistRemove(domain string) {
	ti.t.Helper()
	ti.env.mustRun("allowlist", "remove", ti.name, domain)
}

// allowlistList returns the allowlist domains.
func (ti *testInstance) allowlistList() []string {
	ti.t.Helper()
	result := ti.env.mustRun("allowlist", "list", ti.name)

	var domains []string
	for _, line := range strings.Split(result.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "Allowlist") {
			domains = append(domains, line)
		}
	}
	return domains
}

// skipInShortMode skips the test in fast/smoke mode (-short flag).
// Tests without this call are considered smoke tests and always run.
func skipInShortMode(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
}

// skipIfNoLibvirt skips the test if libvirt is not available.
func skipIfNoLibvirt(t *testing.T) {
	t.Helper()

	// Check if virsh is available
	if _, err := exec.LookPath("virsh"); err != nil {
		t.Skip("virsh not found - libvirt not installed")
	}

	// Check if libvirt daemon is running
	cmd := exec.Command("virsh", "-c", "qemu:///system", "version")
	if err := cmd.Run(); err != nil {
		t.Skip("libvirt daemon not accessible - is libvirtd running?")
	}
}

// skipIfNoBaseImage skips the test if the base image is not available.
func skipIfNoBaseImage(t *testing.T, image string) {
	t.Helper()

	// Check in libvirt images directory first
	imagePath := filepath.Join("/var/lib/libvirt/images/abox/base", image+".qcow2")
	if _, err := os.Stat(imagePath); err == nil {
		return // Found in libvirt directory
	}

	// Also check in user's base images directory (where downloads go)
	home, err := os.UserHomeDir()
	if err == nil {
		userImagePath := filepath.Join(home, ".local/share/abox/base", image+".qcow2")
		if _, err := os.Stat(userImagePath); err == nil {
			return // Found in user directory
		}
	}

	t.Skipf("Base image %s not found - run 'abox base pull %s' first", image, image)
}

// skipIfNoConfiguredBaseImage skips the test if the configured base image (from ABOX_E2E_BASE or default) is not available.
func skipIfNoConfiguredBaseImage(t *testing.T) {
	t.Helper()
	skipIfNoBaseImage(t, getBaseImage())
}

// dumpDiagnostics logs host-side network state for debugging connectivity failures.
func (ti *testInstance) dumpDiagnostics() {
	ti.t.Helper()
	ti.t.Log("=== DIAGNOSTICS: host-side network state ===")

	inst, paths, err := config.Load(ti.name)
	if err != nil {
		ti.t.Logf("Failed to load instance config: %v", err)
		return
	}
	domain := fmt.Sprintf("abox-%s", ti.name)

	ti.t.Logf("Config: MAC=%s IP=%s Gateway=%s Bridge=%s",
		inst.MACAddress, inst.IPAddress, inst.Gateway, inst.Bridge)

	// DHCP leases from libvirt's dnsmasq
	if out, err := exec.Command("virsh", "-c", "qemu:///system",
		"net-dhcp-leases", inst.Bridge).CombinedOutput(); err == nil {
		ti.t.Logf("DHCP leases (%s):\n%s", inst.Bridge, out)
	} else {
		ti.t.Logf("DHCP leases: error: %v\n%s", err, out)
	}

	// domifaddr (lease source)
	if out, err := exec.Command("virsh", "-c", "qemu:///system",
		"domifaddr", domain, "--source", "lease").CombinedOutput(); err == nil {
		ti.t.Logf("domifaddr --source=lease:\n%s", out)
	} else {
		ti.t.Logf("domifaddr --source=lease: error: %v\n%s", err, out)
	}

	// ARP table on bridge
	if out, err := exec.Command("ip", "neigh", "show",
		"dev", inst.Bridge).CombinedOutput(); err == nil {
		ti.t.Logf("ARP table (%s):\n%s", inst.Bridge, out)
	} else {
		ti.t.Logf("ARP table: error: %v\n%s", err, out)
	}

	// Bridge link state
	if out, err := exec.Command("ip", "link", "show",
		inst.Bridge).CombinedOutput(); err == nil {
		ti.t.Logf("Bridge state:\n%s", out)
	}

	// Cloud-init ISO
	ti.t.Logf("CloudInit ISO: %s", paths.CloudInitISO)
	if info, err := os.Stat(paths.CloudInitISO); err == nil {
		ti.t.Logf("CloudInit ISO size: %d bytes", info.Size())
	} else {
		ti.t.Logf("CloudInit ISO: %v", err)
	}

	ti.t.Log("=== END DIAGNOSTICS ===")
}

// skipIfNoSSHFS skips the test if sshfs is not available.
func skipIfNoSSHFS(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("sshfs"); err != nil {
		t.Skip("sshfs not found - install sshfs to run mount tests")
	}
}
