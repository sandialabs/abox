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
//   - ABOX_BACKEND: Select the VM backend under test (default: registry default,
//     i.e. "libvirt"). Mirrors production selection (factory.EnvBackend). Tests
//     skip when the selected backend's IsAvailable() reports false.
//     Example: ABOX_BACKEND=vmware go test -tags=e2e -v ./e2e/...
package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sandialabs/abox/internal/backend"
	// The VM backends self-register via blank imports in the per-OS
	// backends_*_test.go files (libvirt/vmware on Linux, vfkit/vmware on macOS),
	// mirroring production wiring in pkg/cmd/root/backends_<goos>.go. That keeps
	// the darwin (vfkit) build of the e2e suite from pulling in Linux-only
	// backends, while still letting the harness resolve a backend by name for
	// capability-based skips.
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/pkg/cmd/factory"
)

const (
	// defaultTimeout is the default timeout for abox commands
	defaultTimeout = 2 * time.Minute

	// longTimeout is for commands that may take longer (create, start, export/import).
	// Export flattens+archives the full disk; on slower distros this can exceed 5m,
	// so keep headroom above the observed worst case (~4.5m).
	longTimeout = 8 * time.Minute

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

// sub returns a shallow copy of the env bound to the given (sub)test's t. Helpers
// invoked inside a t.Run body must use a sub-bound env/instance: otherwise a must*
// helper's Fatalf runs FailNow on the PARENT t from the subtest goroutine, which Go
// reports as "subtest may have called FailNow on a parent test" and which discards the
// real error. See (*testInstance).sub.
func (e *testEnv) sub(t *testing.T) *testEnv {
	return &testEnv{aboxBinary: e.aboxBinary, t: t}
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

	// Register the failure-diagnostics hook AFTER the removal cleanup above. Cleanups
	// run last-added-first (LIFO), so this dump runs BEFORE ti.cleanup removes the
	// instance and deletes its LogsDir. Ordering here is load-bearing.
	diagnoseOnFailure(e.t, e, name)

	return ti
}

// sub returns a shallow copy of the instance (and its env) bound to the given
// (sub)test's t, so must* helpers called inside a t.Run body fail the subtest cleanly
// instead of calling FailNow on the parent t. Shadow the outer vars at the top of a
// subtest: `env, inst := env.sub(t), inst.sub(t)`.
func (ti *testInstance) sub(t *testing.T) *testInstance {
	return &testInstance{env: ti.env.sub(t), name: ti.name, t: t}
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

// sshProbeTimeout caps each per-attempt SSH probe in waitForSSH. Without a cap the
// probe inherits the 2-minute default command timeout, and a hung connect on macOS
// (OS default ~75s) lets waitForSSH manage only ~2 polls before its own deadline. A
// short cap keeps the loop actually polling within the overall timeout.
const sshProbeTimeout = 15 * time.Second

// waitForSSH waits for SSH to become available.
func (ti *testInstance) waitForSSH(timeout time.Duration) bool {
	ti.t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		result := ti.env.runWithTimeout(sshProbeTimeout, "ssh", ti.name, "--", "echo", "ready")
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

// backendUnderTest returns the name of the backend the e2e suite should exercise.
// It mirrors production selection (factory.EnvBackend / ABOX_BACKEND); when unset
// it falls back to the registry's default (the tried-first non-experimental
// backend, normally "libvirt"). This keeps the harness in lockstep with how abox
// itself picks a backend, so e2e reflects real usage.
func backendUnderTest() string {
	if name := os.Getenv(factory.EnvBackend); name != "" {
		return name
	}
	return backend.DefaultName()
}

// skipIfBackendUnavailable skips the test when the backend under test is not
// available on this host. It resolves the selected backend (ABOX_BACKEND or the
// registry default) and defers to that backend's own IsAvailable() via
// backend.Get, replacing the hard-coded virsh probe so the same tests run for
// whichever backend is selected and cleanly SKIP "when available". For the
// default (libvirt) path this reduces to the libvirt backend's own virsh check.
func skipIfBackendUnavailable(t *testing.T) {
	t.Helper()

	name := backendUnderTest()
	if name == "" {
		t.Skip("no VM backend registered")
	}
	if !backend.IsRegistered(name) {
		t.Skipf("backend %q is not registered", name)
	}
	// backend.Get runs the backend's own IsAvailable(); a non-nil error means the
	// backend is registered but not usable on this host.
	if _, err := backend.Get(name); err != nil {
		t.Skipf("backend %q not available: %v", name, err)
	}

	// Backend-specific READINESS probe. IsAvailable() only checks that the backend's
	// CLI is installed (e.g. virsh on PATH); it does not confirm the control-plane
	// daemon is reachable. Preserve the historical skip behavior of the old
	// skipIfNoLibvirt, which additionally required libvirtd to be running: without
	// this, a host with virsh present but libvirtd down would RUN (and fail) tests
	// that previously SKIPPED. Gated on the backend name so other backends are not
	// subject to a libvirt-specific probe (vmware may add its own probe later).
	switch name {
	case "libvirt":
		if err := exec.Command("virsh", "-c", "qemu:///system", "version").Run(); err != nil {
			t.Skip("libvirt daemon not accessible - is libvirtd running?")
		}
	}
}

// baseImageDirs returns the directories to search for a downloaded base image for
// the backend under test. It routes through the selected backend's StorageDir()
// rather than a hard-coded libvirt path, and also checks the user download cache
// (where `abox base pull` writes) so the default (libvirt) behavior is preserved.
// Callers invoke skipIfBackendUnavailable first, so backend.Get is expected to
// succeed here; if it doesn't, the backend-managed dir is simply omitted.
func baseImageDirs() []string {
	var dirs []string

	// Backend-managed storage (e.g. libvirt's images dir).
	if b, err := backend.Get(backendUnderTest()); err == nil {
		dirs = append(dirs, filepath.Join(b.StorageDir(), "base"))
	}

	// User download cache (backend-neutral; where `abox base pull` writes).
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".local/share/abox/base"))
	}

	return dirs
}

// baseImageExts lists the on-disk base-image extensions to probe, in priority
// order. Most backends keep the downloaded qcow2; the vfkit (macOS) backend
// converts it to a raw image in its StorageDir, so we also accept ".raw" to keep
// base-image discovery working when the backend under test is vfkit.
var baseImageExts = []string{".qcow2", ".raw"}

// skipIfNoBaseImage skips the test if the base image is not available for the
// backend under test.
func skipIfNoBaseImage(t *testing.T, image string) {
	t.Helper()

	for _, dir := range baseImageDirs() {
		for _, ext := range baseImageExts {
			if _, err := os.Stat(filepath.Join(dir, image+ext)); err == nil {
				return // Found
			}
		}
	}

	t.Skipf("Base image %s not found - run 'abox base pull %s' first", image, image)
}

// skipIfNoSnapshotSupport skips the test when the backend under test cannot take
// snapshots. Capability is read from the backend itself: Backend.Snapshot()
// returns nil when snapshots are unsupported (e.g. the vfkit/macOS backend,
// whose raw disks have no snapshot concept). This routes snapshot tests through
// the existing backend-capability seam rather than hard-coding an OS check.
func skipIfNoSnapshotSupport(t *testing.T) {
	t.Helper()

	b, err := backend.Get(backendUnderTest())
	if err != nil {
		t.Skipf("backend %q not available: %v", backendUnderTest(), err)
	}
	if b.Snapshot() == nil {
		t.Skipf("backend %q does not support snapshots", backendUnderTest())
	}
}

// skipIfNoMonitorSupport skips the test when the backend under test cannot carry
// Tetragon monitoring events. Capability is read from the backend itself:
// Backend.MonitorTransport() returns nil when monitoring is unsupported (e.g.
// the vfkit/macOS backend, since Tetragon is eBPF/Linux-only). This routes
// monitor tests through the existing backend-capability seam rather than
// hard-coding an OS check.
func skipIfNoMonitorSupport(t *testing.T) {
	t.Helper()

	b, err := backend.Get(backendUnderTest())
	if err != nil {
		t.Skipf("backend %q not available: %v", backendUnderTest(), err)
	}
	if b.MonitorTransport() == nil {
		t.Skipf("backend %q does not support monitoring", backendUnderTest())
	}
}

// skipIfNoConfiguredBaseImage skips the test if the configured base image (from ABOX_E2E_BASE or default) is not available.
func skipIfNoConfiguredBaseImage(t *testing.T) {
	t.Helper()
	skipIfNoBaseImage(t, getBaseImage())
}

// diagnoseOnFailure registers a cleanup that dumps the instance's diagnostic bundle
// iff t failed. It is keyed to the given t, so it fires at that test/subtest's
// teardown with no cross-scope dedup needed. Callers MUST register it AFTER any
// teardown/remove cleanup so LIFO runs the dump FIRST, before the instance (and its
// LogsDir) is removed.
func diagnoseOnFailure(t *testing.T, env *testEnv, name string) {
	t.Cleanup(func() {
		if t.Failed() {
			dumpInstanceDiagnostics(t, env, name)
		}
	})
}

// dumpInstanceDiagnostics logs a best-effort, backend-neutral snapshot to help debug
// a failed test: host-side network state, a tail of every instance log, live status,
// and (when reachable) the guest cloud-init log. Every step is guarded so it is safe
// on any OS/backend, and it is quick even against an unhealthy VM (shell-outs are
// time-boxed). Callers gate invocation on t.Failed via diagnoseOnFailure.
func dumpInstanceDiagnostics(t *testing.T, env *testEnv, name string) {
	t.Helper()
	t.Logf("=== DIAGNOSTICS [%s]: instance %q ===", t.Name(), name)

	inst, paths, err := config.Load(name)
	if err != nil {
		// No (or partial) instance on disk — nothing useful to dump.
		t.Logf("Failed to load instance config: %v", err)
		return
	}

	backendName := backendUnderTest()

	t.Logf("Backend: %s", backendName)
	t.Logf("Config: MAC=%s IP=%s Gateway=%s Bridge=%s",
		inst.MACAddress, inst.IPAddress, inst.Gateway, inst.Bridge)

	// libvirt-specific address diagnostics (virsh). Gated on the backend name so a
	// vmware run doesn't shell out to virsh. Guests are statically addressed (no
	// DHCP leases exist), so query the host ARP table for the guest's learned
	// address rather than DHCP leases. Reconstruct the VM name via the backend
	// (mirrors (*testInstance).resourceNames) since we have no *testInstance here.
	if backendName == "libvirt" {
		vmName := "abox-" + name
		if b, berr := backend.Get(backendName); berr == nil {
			vmName = b.ResourceNames(name).VM
		}
		if out, err := exec.Command("virsh", "-c", "qemu:///system",
			"domifaddr", vmName, "--source", "arp").CombinedOutput(); err == nil {
			t.Logf("domifaddr --source=arp:\n%s", out)
		} else {
			t.Logf("domifaddr --source=arp: error: %v\n%s", err, out)
		}
	}

	// Host-side bridge diagnostics via `ip` (Linux-only). macOS/vfkit hosts have no
	// `ip` binary, so gate on GOOS to avoid noisy "executable file not found" output.
	// `ip` exists for both libvirt and vmware on Linux, so gate on the OS, not the
	// backend name.
	if runtime.GOOS == "linux" {
		// ARP table on bridge
		if out, err := exec.Command("ip", "neigh", "show",
			"dev", inst.Bridge).CombinedOutput(); err == nil {
			t.Logf("ARP table (%s):\n%s", inst.Bridge, out)
		} else {
			t.Logf("ARP table: error: %v\n%s", err, out)
		}

		// Bridge link state
		if out, err := exec.Command("ip", "link", "show",
			inst.Bridge).CombinedOutput(); err == nil {
			t.Logf("Bridge state:\n%s", out)
		}
	}

	// Cloud-init ISO
	t.Logf("CloudInit ISO: %s", paths.CloudInitISO)
	if info, err := os.Stat(paths.CloudInitISO); err == nil {
		t.Logf("CloudInit ISO size: %d bytes", info.Size())
	} else {
		t.Logf("CloudInit ISO: %v", err)
	}

	// Tail every log the instance produced. Enumerating the directory (rather than a
	// fixed list) auto-captures logs not in the Paths struct — e.g. mount.log (built
	// ad-hoc in pkg/cmd/mount) and console.log/vfkit.log/vmnet-helper.log on macOS —
	// and any log added later, with no test change.
	dumpInstanceLogs(t, paths.LogsDir)

	// Live runtime state. Time-boxed: the VM is unhealthy by definition here, so we
	// must never inherit the 2-minute default command timeout.
	if r := env.runWithTimeout(15*time.Second, "status", name); r.Stdout != "" || r.Stderr != "" {
		t.Logf("=== abox status %s ===\n%s%s", name, r.Stdout, r.Stderr)
	}

	// Guest cloud-init output (best-effort, tight deadline). Requires sudo — the file
	// is root-only (matches the working call in monitor_test.go). Only succeeds when
	// SSH is up; complements host console.log when it is not.
	if r := env.runWithTimeout(15*time.Second, "ssh", name, "--",
		"sudo", "tail", "-n", "100", "/var/log/cloud-init-output.log"); r.Success() {
		t.Logf("=== guest /var/log/cloud-init-output.log (tail) ===\n%s", r.Stdout)
	}

	t.Logf("=== END DIAGNOSTICS [%s] ===", t.Name())
}

// maxLogTailBytes caps how much of each log file dumpInstanceLogs emits.
const maxLogTailBytes = 16 * 1024

// dumpInstanceLogs tails every regular file in logsDir. It skips keys.log (TLS
// session secrets must not land in CI output — it is the only sensitive file under
// LogsDir; SSH/CA keys live in the instance dir, not here) and empty files.
func dumpInstanceLogs(t *testing.T, logsDir string) {
	t.Helper()
	entries, err := os.ReadDir(logsDir)
	if err != nil {
		t.Logf("logs dir %s: %v", logsDir, err)
		return
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == "keys.log" {
			continue
		}
		p := filepath.Join(logsDir, e.Name())
		content, err := tailFile(p, maxLogTailBytes)
		if err != nil {
			t.Logf("tail %s: %v", p, err)
			continue
		}
		if content == "" {
			continue
		}
		t.Logf("=== logs/%s (last %dB) ===\n%s\n=== end logs/%s ===", e.Name(), maxLogTailBytes, content, e.Name())
	}
}

// tailFile returns up to the last maxBytes of a file with non-printable bytes
// stripped. It clamps the read offset to max(0, size-maxBytes) (a negative relative
// Seek would error on short files). Stripping also neutralizes any partial leading
// UTF-8 rune produced by seeking mid-file.
func tailFile(path string, maxBytes int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if fi.Size() == 0 {
		return "", nil
	}
	if offset := fi.Size() - maxBytes; offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return "", err
		}
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return sanitizePrintable(string(data)), nil
}

// sanitizePrintable drops control bytes (keeping tab/newline/carriage-return) so a
// binary-ish log (e.g. a serial console) cannot corrupt test output.
func sanitizePrintable(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t' || r == '\r':
			return r
		case r < 0x20 || r == 0x7f:
			return -1
		default:
			return r
		}
	}, s)
}

// guestHasCommand reports whether the given command exists on the guest's PATH.
// It gates the DNS test on optional guest tooling (nslookup from dnsutils) so a
// missing tool cleanly SKIPs the assertion rather than letting a "must fail"
// check pass for the wrong reason (a command-not-found exit is non-zero and would
// masquerade as "traffic blocked"). Uses the POSIX `command -v` builtin (portable
// to RHEL/Fedora minimal images, which lack `which`); the whole probe is passed
// as a single argument so sshd runs it through the remote login shell verbatim.
func (ti *testInstance) guestHasCommand(cmd string) bool {
	ti.t.Helper()
	return ti.ssh("command -v " + cmd).Success()
}

// tcpConnectCmd renders a bash /dev/tcp TCP connect probe to host:port: it exits
// 0 on an established handshake and non-zero on refuse (bash connect failure) or
// drop (the 3s timeout kills it, exit 124) — equivalent to python3's connect_ex.
// bash is the login shell on every target image (unlike python3, which is absent
// on the almalinux-8 minimal image), and /dev/tcp is a bash builtin, so this is
// the portable primitive for the guest→host reachability gate.
func tcpConnectCmd(host string, port int) string {
	return fmt.Sprintf("timeout 3 bash -c 'exec 3<>/dev/tcp/%s/%d'", host, port)
}

// guestCanConnect runs the TCP connect probe from inside the guest and returns the
// result; Success() means the TCP handshake to host:port completed.
func (ti *testInstance) guestCanConnect(host string, port int) *runResult {
	ti.t.Helper()
	return ti.ssh(tcpConnectCmd(host, port))
}

// gatewayAndPorts loads the instance's host-side gateway IP and the DNS/HTTP
// filter ports from its persisted config. These identify the only gateway ports
// the guest is permitted to reach (the dnsfilter and httpfilter listeners);
// every other host port must be unreachable from the guest.
func (ti *testInstance) gatewayAndPorts() (gateway string, dnsPort, httpPort int) {
	ti.t.Helper()
	inst, _, err := config.Load(ti.name)
	if err != nil {
		ti.t.Fatalf("config.Load(%s): %v", ti.name, err)
	}
	return inst.Gateway, inst.DNS.Port, inst.HTTP.Port
}

// dnsResolved reports whether an nslookup runResult represents a successful
// resolution (an answer was returned) rather than a block or failure. nslookup's
// exit status is not fully portable across versions, so we also scan for the
// well-known failure markers emitted by our dnsfilter (NXDOMAIN on a blocked
// domain) and by the resolver stack when the query never reaches a server
// (timeout/SERVFAIL/REFUSED). This lets the same helper distinguish "our filter
// captured and answered/blocked this" from "the packet went nowhere".
func dnsResolved(r *runResult) bool {
	out := r.Stdout + r.Stderr
	for _, marker := range []string{
		"NXDOMAIN", "SERVFAIL", "REFUSED",
		"can't find", "timed out", "no servers could be reached",
	} {
		if strings.Contains(out, marker) {
			return false
		}
	}
	return r.Success()
}

// skipIfNoSSHFS skips the test if sshfs is not available.
func skipIfNoSSHFS(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("sshfs"); err != nil {
		t.Skip("sshfs not found - install sshfs to run mount tests")
	}
}

// readPID polls pidFile until it appears and contains a valid PID, then returns it.
// Fails the test if the file never appears or contains an unparseable PID.
func readPID(t *testing.T, pidFile string) int {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(pidFile)
		if err == nil {
			pid, perr := strconv.Atoi(strings.TrimSpace(string(data)))
			if perr == nil && pid > 0 {
				return pid
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("PID file %s did not appear with a valid PID within 30s", pidFile)
	return 0
}

// waitForDead waits until the process with the given PID is no longer running.
// Fails the test if the process is still alive after the timeout.
func waitForDead(t *testing.T, pid int) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		// signal 0 checks existence without sending a signal
		if err := syscall.Kill(pid, 0); err != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("process %d did not die within 10s", pid)
}
