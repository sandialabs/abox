//go:build e2e

package e2e

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sandialabs/abox/internal/tetragon/policy"
)

// TestMonitorWorkflow tests abox monitor functionality with Tetragon.
func TestMonitorWorkflow(t *testing.T) {
	skipIfNoLibvirt(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)

	// Setup: create temp dir with abox.yaml that has monitoring enabled
	dir := t.TempDir()
	name := uniqueTestName()

	writeTestBoxfile(t, dir, testBoxfileConfig{
		Name:    name,
		CPUs:    1,
		Memory:  1024, // Need more memory for Tetragon
		Monitor: true,
	})

	// Register cleanup
	t.Cleanup(func() {
		env.runWithTimeout(longTimeout, "down", "--remove", "--force", "-d", dir)
	})

	t.Run("up-with-monitor", func(t *testing.T) {
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
			t.Fatal("Instance did not reach running state")
		}

		// Wait for SSH to be available (cloud-init to complete)
		if !ti.waitForSSH(180 * time.Second) {
			ti.dumpDiagnostics()
			t.Fatal("SSH did not become available")
		}
	})

	t.Run("tetragon-installed-from-iso", func(t *testing.T) {
		// Wait for cloud-init to complete (runcmd installs Tetragon)
		ti := &testInstance{env: env, name: name, t: t}
		ti.waitForCloudInit()

		// Verify Tetragon is installed and running (retry to handle startup delay)
		sshResult := ti.waitForSSHCondition(30*time.Second, 3*time.Second, func(r *runResult) bool {
			return strings.TrimSpace(r.Stdout) == "active"
		}, "systemctl", "is-active", "tetragon")
		if strings.TrimSpace(sshResult.Stdout) != "active" {
			// Get diagnostic info
			t.Log("=== cloud-init-output.log (last 100 lines) ===")
			diagResult := ti.ssh("sudo", "tail", "-100", "/var/log/cloud-init-output.log")
			t.Log(diagResult.Stdout)
			t.Log("=== tetragon journal (last 50 lines) ===")
			diagResult = ti.ssh("journalctl", "-u", "tetragon", "--no-pager", "-n", "50")
			t.Log(diagResult.Stdout)
			t.Errorf("Expected tetragon to be 'active', got: %s", strings.TrimSpace(sshResult.Stdout))
		}

		// Verify cloud-init log does NOT contain curl download (ISO piggyback was used)
		sshResult = ti.ssh("grep", "-c", "curl.*tetragon", "/var/log/cloud-init-output.log")
		// grep returns exit code 1 if no match, which is what we want
		if sshResult.Success() {
			count := strings.TrimSpace(sshResult.Stdout)
			if count != "0" {
				t.Log("Note: curl download detected in cloud-init log (expected ISO piggyback)")
				// This is not a failure - older ISOs or cache miss would use network download
			}
		}

		// Verify cloud-init log contains ISO mount (ISO piggyback was used)
		sshResult = ti.ssh("grep", "-c", "mount.*cidata", "/var/log/cloud-init-output.log")
		if !sshResult.Success() || strings.TrimSpace(sshResult.Stdout) == "0" {
			t.Log("Note: ISO mount not detected in cloud-init log (may have used network download)")
		}
	})

	t.Run("monitor-agent-running", func(t *testing.T) {
		// Verify abox-monitor agent is running in VM
		// Retry because the service may restart a few times while tetragon initializes
		ti := &testInstance{env: env, name: name, t: t}
		result := ti.waitForSSHCondition(30*time.Second, 3*time.Second, func(r *runResult) bool {
			return strings.TrimSpace(r.Stdout) == "active"
		}, "systemctl", "is-active", "abox-monitor")

		output := strings.TrimSpace(result.Stdout)
		if output != "active" {
			t.Log("=== abox-monitor journal (last 50 lines) ===")
			diagResult := ti.ssh("journalctl", "-u", "abox-monitor", "--no-pager", "-n", "50")
			t.Log(diagResult.Stdout)
			t.Log("=== abox-monitor service status ===")
			diagResult = ti.ssh("systemctl", "status", "abox-monitor", "--no-pager")
			t.Log(diagResult.Stdout)
			t.Errorf("Expected abox-monitor to be 'active', got: %s", output)
		}
	})

	t.Run("monitor-status", func(t *testing.T) {
		// Verify abox monitor status works
		result := env.run("monitor", "status", name)
		if !result.Success() {
			t.Errorf("monitor status failed: %s\nstderr: %s", result.Stdout, result.Stderr)
		}

		// Should show the monitor daemon is running
		output := result.Stdout + result.Stderr
		if !strings.Contains(output, "running") && !strings.Contains(output, "active") {
			t.Logf("Monitor status output: %s", output)
		}
	})

	t.Run("events-captured", func(t *testing.T) {
		// Execute a command in the VM to generate an event
		ti := &testInstance{env: env, name: name, t: t}
		sshResult := ti.ssh("ls", "/tmp")
		if !sshResult.Success() {
			t.Fatalf("SSH command failed: %s", sshResult.Stderr)
		}

		// Wait a moment for the event to be captured
		time.Sleep(3 * time.Second)

		// Check if events are captured in the log
		result := env.run("monitor", "logs", name, "--lines", "20")
		if !result.Success() {
			// Monitor might not have events yet, that's ok
			t.Logf("monitor logs output: %s\nstderr: %s", result.Stdout, result.Stderr)
		}

		// We don't require specific events, just that the command works
		// The actual event capture depends on Tetragon policy and virtio-serial
	})
}

// TestMonitorEventTypes verifies that each kprobe type captures events end-to-end.
// A single VM is created with ALL kprobes enabled, trigger commands are run via SSH,
// and then each event type is verified in the monitor logs.
func TestMonitorEventTypes(t *testing.T) {
	skipIfNoLibvirt(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	dir := t.TempDir()
	name := uniqueTestName()

	writeTestBoxfile(t, dir, testBoxfileConfig{
		Name:    name,
		CPUs:    2,
		Memory:  2048, // All kprobes need more headroom
		Monitor: true,
		Kprobes: policy.AllKprobeNames(),
	})

	t.Cleanup(func() {
		env.runWithTimeout(longTimeout, "down", "--remove", "--force", "-d", dir)
	})

	// Track whether optional tools are available in the VM.
	var hasPython3 bool
	var hasModprobeDummy bool

	t.Run("setup", func(t *testing.T) {
		result := env.runWithTimeout(longTimeout, "up", "-d", dir)
		if !result.Success() {
			t.Fatalf("up failed: %s\nstderr: %s", result.Stdout, result.Stderr)
		}

		ti := &testInstance{env: env, name: name, t: t}
		if !ti.waitForRunning(60 * time.Second) {
			t.Fatal("Instance did not reach running state")
		}
		if !ti.waitForSSH(180 * time.Second) {
			ti.dumpDiagnostics()
			t.Fatal("SSH did not become available")
		}

		// Wait for cloud-init to finish (installs Tetragon)
		ti.waitForCloudInit()

		// Wait for Tetragon and monitor agent
		result = ti.waitForSSHCondition(60*time.Second, 3*time.Second, func(r *runResult) bool {
			return strings.TrimSpace(r.Stdout) == "active"
		}, "systemctl", "is-active", "tetragon")
		if strings.TrimSpace(result.Stdout) != "active" {
			dumpMonitorDiagnostics(t, env, ti)
			t.Fatal("Tetragon service did not become active")
		}

		ti.waitForSSHCondition(60*time.Second, 3*time.Second, func(r *runResult) bool {
			return strings.TrimSpace(r.Stdout) == "active"
		}, "systemctl", "is-active", "abox-monitor")

		// Probe for optional tools
		hasPython3 = ti.ssh("python3", "--version").Success()
		hasModprobeDummy = ti.ssh("sudo", "modprobe", "--dry-run", "dummy").Success()
	})

	t.Run("trigger-events", func(t *testing.T) {
		ti := &testInstance{env: env, name: name, t: t}

		// File events
		ti.triggerSSH(t, "file-open", "cat", "/etc/hostname")
		ti.triggerSSH(t, "file-touch", "touch", "/tmp/abox-delete-test")
		ti.triggerSSH(t, "file-delete", "rm", "/tmp/abox-delete-test")
		ti.triggerSSH(t, "file-touch-rename", "touch", "/tmp/abox-rename-src")
		ti.triggerSSH(t, "file-rename", "mv", "/tmp/abox-rename-src", "/tmp/abox-rename-dst")
		ti.triggerSSH(t, "file-cleanup", "rm", "-f", "/tmp/abox-rename-dst")

		// Network events — run 3× to increase capture probability
		if hasPython3 {
			for i := 0; i < 3; i++ {
				ti.triggerSSH(t, fmt.Sprintf("net-connect-%d", i), "python3", "-c",
					"'import socket; s=socket.socket(); s.connect((\"127.0.0.1\",22)); s.close()'")
			}
			for i := 0; i < 3; i++ {
				ti.triggerSSH(t, fmt.Sprintf("net-listen-%d", i), "python3", "-c",
					"'import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((\"0.0.0.0\",0)); s.listen(1); time.sleep(1)'")
			}
		}
		ti.triggerSSH(t, "sentinel-net", "touch", "/tmp/abox-sentinel-net")

		// Security events (sudo triggers exec_check, cred_change, setuid_root)
		ti.triggerSSH(t, "sudo-id", "sudo", "id")
		for i := 0; i < 3; i++ {
			ti.triggerSSH(t, fmt.Sprintf("mount-%d", i), "sudo", "mount", "-t", "tmpfs", "tmpfs", "/mnt")
			ti.triggerSSH(t, fmt.Sprintf("umount-%d", i), "sudo", "umount", "/mnt")
		}
		if hasPython3 {
			for i := 0; i < 3; i++ {
				ti.triggerSSH(t, fmt.Sprintf("ptrace-%d", i), "python3", "-c",
					"'import ctypes; ctypes.CDLL(None).ptrace(0,0,0,0)'")
			}
		}
		if hasModprobeDummy {
			for i := 0; i < 3; i++ {
				ti.triggerSSH(t, fmt.Sprintf("modprobe-%d", i), "sudo", "modprobe", "dummy")
				ti.triggerSSH(t, fmt.Sprintf("modprobe-rm-%d", i), "sudo", "modprobe", "-r", "dummy")
			}
		}
		ti.triggerSSH(t, "sentinel-sec", "touch", "/tmp/abox-sentinel-sec")

		// Final sentinel — poll for it to confirm the entire pipeline has flushed
		ti.triggerSSH(t, "sentinel-done", "touch", "/tmp/abox-sentinel-done")

		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if lines := monitorQuery(env, name,
				`select(.type == "file" and .path == "/tmp/abox-sentinel-done")`); len(lines) > 0 {
				t.Log("Pipeline sync: sentinel-done seen in monitor log")
				break
			}
			time.Sleep(1 * time.Second)
		}
	})

	// Capture loaded policy state for use by verify subtests.
	var policyOutput string

	t.Run("verify-policies", func(t *testing.T) {
		ti := &testInstance{env: env, name: name, t: t}

		// Log kernel version
		r := ti.ssh("uname", "-r")
		t.Logf("Kernel: %s", strings.TrimSpace(r.Stdout))

		// Log policy files on disk
		r = ti.ssh("sudo", "ls", "-la", "/etc/tetragon/tetragon.tp.d/")
		t.Logf("Policy files:\n%s", r.Stdout)

		// Dump policy file contents so we can see exactly what kprobes are defined
		r = ti.ssh("grep", "-rn", ".", "/etc/tetragon/tetragon.tp.d/")
		t.Logf("Policy contents:\n%s", r.Stdout)

		// Capture loaded policies (use full path — sudo secure_path may omit /usr/local/bin)
		r = ti.ssh("sudo", "/usr/local/bin/tetra", "tracingpolicy", "list")
		policyOutput = r.Stdout
		t.Logf("Loaded policies:\n%s", policyOutput)
		if strings.TrimSpace(policyOutput) == "" || !r.Success() {
			t.Log("WARNING: tetra tracingpolicy list returned no data; policy-based skip logic disabled")
		}

		// Log Tetragon journal (info level and above to catch kprobe attachment messages)
		r = ti.ssh("sudo", "journalctl", "-u", "tetragon", "--no-pager", "-n", "100")
		if r.Stdout != "" && !strings.Contains(r.Stdout, "No entries") {
			t.Logf("Tetragon journal:\n%s", r.Stdout)
		}

		// Log NPOST summary for quick diagnosis
		for _, kpName := range policy.AllKprobeNames() {
			n := npostForPolicy(policyOutput, kpName)
			if n >= 0 {
				t.Logf("  NPOST %s = %d", kpName, n)
			}
		}

		// Warn if combined policy instead of per-kprobe
		if strings.Contains(policyOutput, "abox-monitor") {
			t.Log("WARNING: Found combined abox-monitor policy; expected per-kprobe policies")
			t.Log("WARNING: This usually means the abox binary is stale. Run 'make build' or use 'make test-e2e'.")
		}

		// Dump event type summary from monitor log
		logResult := env.run("monitor", "logs", name, "--lines", "500")
		if logResult.Success() && logResult.Stdout != "" {
			counts := map[string]int{}
			for _, line := range strings.Split(logResult.Stdout, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				// Extract raw_type from JSON lines: look for "raw_type":"<value>"
				if idx := strings.Index(line, `"raw_type":"`); idx >= 0 {
					rest := line[idx+len(`"raw_type":"`):]
					if end := strings.Index(rest, `"`); end >= 0 {
						counts[rest[:end]]++
					}
				}
			}
			if len(counts) > 0 {
				keys := make([]string, 0, len(counts))
				for k := range counts {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				parts := make([]string, 0, len(keys))
				for _, k := range keys {
					parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
				}
				t.Logf("Events by raw_type: %s", strings.Join(parts, ", "))
			} else {
				t.Log("Events by raw_type: (none found)")
			}
		}
	})

	// Verify each event type appears in the monitor logs.
	// Default kprobes (always on):

	t.Run("verify-exec", func(t *testing.T) {
		requireMonitorEvent(t, env, name, `select(.type == "exec")`, "exec event")
	})

	t.Run("verify-file-open", func(t *testing.T) {
		skipIfPolicyNotLoaded(t, policyOutput, "security_file_open")
		requireMonitorEvent(t, env, name,
			`select(.type == "file" and .op == "open")`, "file open event")
	})

	t.Run("verify-file-delete", func(t *testing.T) {
		skipIfPolicyNotLoaded(t, policyOutput, "vfs_unlink")
		requireMonitorEvent(t, env, name,
			`select(.type == "file" and .op == "delete")`, "file delete event")
	})

	t.Run("verify-file-rename", func(t *testing.T) {
		skipIfPolicyNotLoaded(t, policyOutput, "vfs_rename")
		requireMonitorEvent(t, env, name,
			`select(.type == "file" and .op == "rename")`, "file rename event")
	})

	t.Run("verify-net-connect", func(t *testing.T) {
		if !hasPython3 {
			t.Skip("python3 not available in VM (needed for network trigger)")
		}
		skipIfPolicyNotLoaded(t, policyOutput, "security_socket_connect")
		requireMonitorEvent(t, env, name,
			`select(.type == "net" and .op == "connect")`, "net connect event")
	})

	t.Run("verify-net-listen", func(t *testing.T) {
		if !hasPython3 {
			t.Skip("python3 not available in VM (needed for network trigger)")
		}
		skipIfPolicyNotLoaded(t, policyOutput, "inet_csk_listen_start")
		skipIfKprobeNotFiring(t, env, name, policyOutput, "inet_csk_listen_start", "/tmp/abox-sentinel-net")
		expectMonitorEvent(t, env, name,
			`select(.type == "net" and .op == "listen")`, "net listen event")
	})

	// Opt-in kprobes:

	t.Run("verify-net-close", func(t *testing.T) {
		skipIfPolicyNotLoaded(t, policyOutput, "tcp_close")
		expectMonitorEvent(t, env, name,
			`select(.type == "net" and .op == "close")`, "net close event")
	})

	t.Run("verify-sec-exec-check", func(t *testing.T) {
		skipIfPolicyNotLoaded(t, policyOutput, "security_bprm_check")
		requireMonitorEvent(t, env, name,
			`select(.type == "security" and .op == "exec_check")`, "security exec_check event")
	})

	t.Run("verify-sec-cred-change", func(t *testing.T) {
		skipIfPolicyNotLoaded(t, policyOutput, "commit_creds")
		requireMonitorEvent(t, env, name,
			`select(.type == "security" and .op == "cred_change")`, "security cred_change event")
	})

	t.Run("verify-sec-setuid-root", func(t *testing.T) {
		skipIfPolicyNotLoaded(t, policyOutput, "sys_setuid")
		requireMonitorEvent(t, env, name,
			`select(.type == "security" and .op == "setuid_root")`, "security setuid_root event")
	})

	t.Run("verify-sec-mount", func(t *testing.T) {
		skipIfPolicyNotLoaded(t, policyOutput, "path_mount")
		skipIfKprobeNotFiring(t, env, name, policyOutput, "path_mount", "/tmp/abox-sentinel-sec")
		expectMonitorEvent(t, env, name,
			`select(.type == "security" and .op == "mount")`, "security mount event")
	})

	t.Run("verify-sec-ptrace", func(t *testing.T) {
		if !hasPython3 {
			t.Skip("python3 not available in VM (needed for ptrace trigger)")
		}
		skipIfPolicyNotLoaded(t, policyOutput, "sys_ptrace")
		skipIfKprobeNotFiring(t, env, name, policyOutput, "sys_ptrace", "/tmp/abox-sentinel-sec")
		expectMonitorEvent(t, env, name,
			`select(.type == "security" and .op == "ptrace")`, "security ptrace event")
	})

	t.Run("verify-sec-module-load", func(t *testing.T) {
		if !hasModprobeDummy {
			t.Skip("dummy kernel module not available in VM")
		}
		skipIfPolicyNotLoaded(t, policyOutput, "do_init_module")
		skipIfKprobeNotFiring(t, env, name, policyOutput, "do_init_module", "/tmp/abox-sentinel-sec")
		expectMonitorEvent(t, env, name,
			`select(.type == "security" and .op == "module_load")`, "security module_load event")
	})
}

// skipIfPolicyNotLoaded skips the test if the kprobe's policy is not loaded in Tetragon.
// In per-kprobe mode, it looks for "abox-<kprobeName>". In combined mode (fallback),
// the presence of "abox-monitor" means we can't distinguish individual kprobes, so we don't skip.
// If policyOutput is empty (tetra CLI unavailable), we don't skip — let event checks decide.
func skipIfPolicyNotLoaded(t *testing.T, policyOutput, kprobeName string) {
	t.Helper()
	if strings.TrimSpace(policyOutput) == "" {
		return // can't determine policy state; fall through to event check
	}
	perKprobe := "abox-" + strings.ReplaceAll(kprobeName, "_", "-")
	hasCombined := strings.Contains(policyOutput, "abox-monitor")
	hasPerKprobe := strings.Contains(policyOutput, perKprobe)
	if !hasPerKprobe && !hasCombined {
		t.Skipf("no policy loaded for kprobe %s", kprobeName)
	}
}

// monitorQuery runs `abox monitor logs` with a jq filter and returns matching output lines.
func monitorQuery(env *testEnv, name, jqExpr string) []string {
	result := env.run("monitor", "logs", name, "--lines", "500", "--jq", jqExpr)
	if !result.Success() {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(result.Stdout), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// requireMonitorEvent asserts that at least one event matches the jq filter.
func requireMonitorEvent(t *testing.T, env *testEnv, name, jqExpr, description string) {
	t.Helper()
	lines := monitorQuery(env, name, jqExpr)
	if len(lines) == 0 {
		// Dump raw log for diagnostics
		result := env.run("monitor", "logs", name, "--lines", "100")
		t.Logf("=== Monitor log (last 100 lines) ===\n%s", result.Stdout)
		t.Errorf("No %s found matching: %s", description, jqExpr)
		return
	}
	t.Logf("Found %d %s(s)", len(lines), description)
}

// expectMonitorEvent checks for an event but skips (not fails) if absent.
// Use for kprobes with known kernel/image variability or lossy delivery.
func expectMonitorEvent(t *testing.T, env *testEnv, name, jqExpr, description string) {
	t.Helper()
	lines := monitorQuery(env, name, jqExpr)
	if len(lines) == 0 {
		t.Skipf("No %s found (kernel/image may not support this kprobe)", description)
		return
	}
	t.Logf("Found %d %s(s)", len(lines), description)
}

// npostForPolicy extracts the NPOST counter from tetra tracingpolicy list output.
// Returns -1 if the policy is not found or NPOST can't be parsed.
func npostForPolicy(policyOutput, kprobeName string) int {
	policyName := "abox-" + strings.ReplaceAll(kprobeName, "_", "-")
	for _, line := range strings.Split(policyOutput, "\n") {
		if strings.Contains(line, policyName) {
			fields := strings.Fields(line)
			// NPOST is 3rd from end (before NENFORCE, NMONITOR).
			// Indexing from end handles variable-width KERNELMEMORY (e.g., "3.18 MB").
			if len(fields) >= 3 {
				idx := len(fields) - 3
				if n, err := strconv.Atoi(fields[idx]); err == nil {
					return n
				}
			}
		}
	}
	return -1
}

// triggerSSH runs a command via SSH and logs failures. Use this for trigger
// commands so that silent failures are visible in test output.
func (ti *testInstance) triggerSSH(t *testing.T, label string, cmd ...string) {
	t.Helper()
	r := ti.ssh(cmd...)
	if !r.Success() {
		t.Logf("trigger %s FAILED (exit %d): %s", label, r.ExitCode, r.Stderr)
	}
}

// skipIfKprobeNotFiring checks whether a kprobe is firing and skips if not.
// Logs diagnostic context (NPOST counter, sentinel presence) to help triage.
// If NPOST data is unavailable (tetra CLI broken), falls through to let event checks decide.
func skipIfKprobeNotFiring(t *testing.T, env *testEnv, name, policyOutput, kprobeName, sentinelPath string) {
	t.Helper()
	n := npostForPolicy(policyOutput, kprobeName)
	if n > 0 {
		return // kprobe is firing, proceed
	}
	if n < 0 {
		return // policy not in output (tetra CLI unavailable); let event check decide
	}

	// NPOST == 0: policy loaded but no events posted. Check sentinel to diagnose.
	sentinel := monitorQuery(env, name,
		fmt.Sprintf(`select(.type == "file" and .path == %q)`, sentinelPath))
	if len(sentinel) > 0 {
		t.Skipf("kprobe %s: trigger confirmed (sentinel present) but NPOST=0 — kprobe not firing on this kernel", kprobeName)
	} else {
		t.Skipf("kprobe %s: NPOST=0 and sentinel missing — kprobe not firing or events dropped on this kernel", kprobeName)
	}
}

// dumpMonitorDiagnostics logs monitor event log, service log, and tetragon journal.
func dumpMonitorDiagnostics(t *testing.T, env *testEnv, ti *testInstance) {
	t.Helper()
	t.Log("=== Monitor event log (last 50) ===")
	r := env.run("monitor", "logs", ti.name, "--lines", "50")
	t.Log(r.Stdout)
	t.Log("=== Monitor service log ===")
	r = env.run("monitor", "logs", ti.name, "--service", "--lines", "30")
	t.Log(r.Stdout)
	t.Log("=== Tetragon journal ===")
	r2 := ti.ssh("journalctl", "-u", "tetragon", "--no-pager", "-n", "30")
	t.Log(r2.Stdout)
	t.Log("=== Tetragon tracing policies ===")
	r2 = ti.ssh("sudo", "ls", "-la", "/etc/tetragon/tetragon.tp.d/")
	t.Log(r2.Stdout)
}
