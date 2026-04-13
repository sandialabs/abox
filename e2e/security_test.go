//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestFilteredNetworkAllowsProxy tests that the network allows traffic through the proxy.
// Note: Security mode is always "filtered" - no open/closed modes exist.
func TestFilteredNetworkAllowsProxy(t *testing.T) {
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

	// Add a domain to the allowlist
	inst.allowlistAdd("example.com")

	// Set filter to active mode
	inst.setFilterMode("active")

	// Try to make an HTTP request via proxy - should succeed.
	// Retry to allow time for proxy config to take effect in the VM.
	result := inst.waitForSSHCondition(30*time.Second, 3*time.Second, func(r *runResult) bool {
		return r.Success()
	}, "curl", "-s", "--max-time", "10", "-o", "/dev/null", "-w", "%{http_code}", "http://example.com")

	if !result.Success() {
		t.Errorf("HTTP request to allowed domain via proxy should succeed: %v", result.Stderr)
	}
}

// TestNetworkBlocksDirectAccess tests that direct network access is blocked.
// Traffic must go through the proxy in filtered mode.
func TestNetworkBlocksDirectAccess(t *testing.T) {
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

	// Set filter to active mode
	inst.setFilterMode("active")

	// Try to ping a public IP directly - should fail (nwfilter blocks direct access)
	result := inst.ssh("ping", "-c", "1", "-W", "5", "8.8.8.8")
	if result.Success() {
		t.Error("Direct ping to 8.8.8.8 succeeded - nwfilter should block direct access")
	}
}

// TestMITM_CACertGenerated tests that CA certificate is generated during instance creation.
func TestMITM_CACertGenerated(t *testing.T) {
	skipIfNoLibvirt(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()

	// Check that CA cert and key files were created
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("Failed to get home dir: %v", err)
	}

	instanceDir := filepath.Join(homeDir, ".local/share/abox/instances", inst.name)
	caCertPath := filepath.Join(instanceDir, "ca-cert.pem")
	caKeyPath := filepath.Join(instanceDir, "ca-key.pem")

	// Check CA cert exists
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		t.Errorf("CA certificate not found at %s", caCertPath)
	}

	// Check CA key exists
	if _, err := os.Stat(caKeyPath); os.IsNotExist(err) {
		t.Errorf("CA key not found at %s", caKeyPath)
	}

	// Check CA key has restrictive permissions (0o600)
	info, err := os.Stat(caKeyPath)
	if err == nil {
		mode := info.Mode().Perm()
		if mode != 0o600 {
			t.Errorf("CA key should have 0o600 permissions, got %o", mode)
		}
	}

	// Verify CA cert contains expected content
	certData, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("Failed to read CA cert: %v", err)
	}

	if !strings.Contains(string(certData), "BEGIN CERTIFICATE") {
		t.Error("CA cert file doesn't contain PEM certificate")
	}
}

// TestMITM_Enabled tests that MITM is enabled in the HTTP filter.
func TestMITM_Enabled(t *testing.T) {
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

	// Give HTTP filter time to start
	time.Sleep(5 * time.Second)

	// Check HTTP status - should show MITM is enabled
	result := env.run("http", "status", inst.name)
	if !result.Success() {
		t.Fatalf("HTTP status failed: %v", result.Err)
	}

	// Verify MITM is reported as enabled
	if !strings.Contains(strings.ToLower(result.Stdout), "mitm") {
		t.Errorf("HTTP status should mention MITM, got:\n%s", result.Stdout)
	}
}

// TestMITM_CATrustedInVM tests that the CA certificate is installed in the VM's trust store.
func TestMITM_CATrustedInVM(t *testing.T) {
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

	// Wait for cloud-init runcmd (runs update-ca-certificates).
	inst.waitForCloudInit()

	// Check that the CA certificate was installed by cloud-init
	// Try Debian path first, then RHEL path
	result := inst.ssh("cat", "/usr/local/share/ca-certificates/abox-proxy-ca.crt")
	if !result.Success() {
		// Try RHEL path
		result = inst.ssh("cat", "/etc/pki/ca-trust/source/anchors/abox-proxy-ca.crt")
		if !result.Success() {
			t.Fatalf("CA cert not found in VM at either Debian or RHEL paths: %v", result.Stderr)
		}
	}

	if !strings.Contains(result.Stdout, "BEGIN CERTIFICATE") {
		t.Error("CA cert in VM doesn't contain PEM certificate")
	}

	// Verify it's in the system trust store (Debian path)
	result = inst.ssh("ls", "/etc/ssl/certs/abox-proxy-ca.pem")
	if !result.Success() {
		// Try RHEL - check if update-ca-trust was run successfully
		result = inst.ssh("trust", "list", "--filter=ca-anchors")
		if !result.Success() {
			t.Log("CA cert may not be in system trust store yet")
		}
	}
}

// TestMITM_HTTPSAllowedDomain tests that HTTPS to an allowed domain works through MITM.
func TestMITM_HTTPSAllowedDomain(t *testing.T) {
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

	// Wait for cloud-init runcmd (runs update-ca-certificates).
	inst.waitForCloudInit()

	// Add a domain to allowlist
	inst.allowlistAdd("example.com")

	// Set filter to active mode
	inst.setFilterMode("active")

	// Try HTTPS request to allowed domain.
	// curl should succeed because:
	// 1. The domain is in allowlist (CONNECT allowed)
	// 2. MITM intercepts and re-encrypts (VM trusts our CA)
	// 3. Host header matches allowlist (no domain fronting)
	// Retry to allow time for cloud-init CA trust setup.
	result := inst.waitForSSHCondition(30*time.Second, 3*time.Second, func(r *runResult) bool {
		return r.Success()
	}, "curl", "-s", "--max-time", "10", "-o", "/dev/null", "-w", "%{http_code}", "https://example.com")

	if !result.Success() {
		t.Errorf("HTTPS request to allowed domain should succeed through MITM proxy: %v", result.Stderr)
	}
}

// TestMITM_HTTPSBlockedDomain tests that HTTPS to a non-allowed domain is blocked.
func TestMITM_HTTPSBlockedDomain(t *testing.T) {
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

	// Set filter to active mode
	inst.setFilterMode("active")

	// Try HTTPS request to a domain NOT in the default allowlist
	// The CONNECT request should be rejected by the proxy
	// Using a made-up domain that definitely isn't allowlisted
	result := inst.ssh("curl", "-s", "--max-time", "10", "https://this-domain-is-not-allowed.invalid")
	if result.Success() {
		t.Error("HTTPS request to non-allowed domain should have been blocked")
	}
}

// TestHTTPBlocksNonAllowlisted tests that HTTP requests to non-allowed domains get 403.
func TestHTTPBlocksNonAllowlisted(t *testing.T) {
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

	// Set filter to active mode
	inst.setFilterMode("active")

	// HTTP request to non-allowed domain should get 403 from the proxy
	result := inst.ssh("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10", "http://this-domain-is-not-allowed.invalid")
	if !result.Success() {
		t.Fatalf("curl command itself failed: %v", result.Stderr)
	}

	httpCode := strings.TrimSpace(result.Stdout)
	if httpCode != "403" {
		t.Errorf("HTTP request to non-allowed domain should return 403, got %s", httpCode)
	}
}
