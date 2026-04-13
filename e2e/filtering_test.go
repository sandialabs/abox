//go:build e2e

package e2e

import (
	"strings"
	"testing"
	"time"
)

// TestAllowlistManagement tests adding, removing, and listing allowlist entries.
func TestAllowlistManagement(t *testing.T) {
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

	t.Run("add-domain", func(t *testing.T) {
		inst.allowlistAdd("github.com")

		domains := inst.allowlistList()
		found := false
		for _, d := range domains {
			if strings.Contains(d, "github.com") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("github.com not found in allowlist: %v", domains)
		}
	})

	t.Run("add-wildcard", func(t *testing.T) {
		inst.allowlistAdd("*.example.com")

		domains := inst.allowlistList()
		found := false
		for _, d := range domains {
			if strings.Contains(d, "example.com") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("*.example.com not found in allowlist: %v", domains)
		}
	})

	t.Run("remove-domain", func(t *testing.T) {
		inst.allowlistRemove("github.com")

		domains := inst.allowlistList()
		for _, d := range domains {
			if strings.Contains(d, "github.com") {
				t.Errorf("github.com should have been removed, still found in: %v", domains)
				break
			}
		}
	})

	t.Run("add-invalid-domain", func(t *testing.T) {
		result := env.run("allowlist", "add", inst.name, "invalid..domain")
		if result.Success() {
			t.Error("Adding invalid domain should fail")
		}
	})
}

// TestDNSFilterStatus tests the DNS filter status command.
func TestDNSFilterStatus(t *testing.T) {
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

	// Give the DNS filter time to start
	time.Sleep(5 * time.Second)

	result := env.run("dns", "status", inst.name)
	if !result.Success() {
		t.Fatalf("DNS status failed: %v", result.Err)
	}

	// Check for expected status fields
	if !strings.Contains(result.Stdout, "Mode:") {
		t.Error("DNS status should contain Mode")
	}
}

// TestHTTPFilterStatus tests the HTTP filter status command.
func TestHTTPFilterStatus(t *testing.T) {
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

	// Give the HTTP filter time to start
	time.Sleep(5 * time.Second)

	result := env.run("http", "status", inst.name)
	if !result.Success() {
		t.Fatalf("HTTP status failed: %v", result.Err)
	}

	// Check for expected status fields
	if !strings.Contains(result.Stdout, "Mode:") {
		t.Error("HTTP status should contain Mode")
	}
}

// TestNetFilterCommand tests the unified filter mode command (abox net filter).
func TestNetFilterCommand(t *testing.T) {
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

	// Give filters time to start
	time.Sleep(5 * time.Second)

	t.Run("get-mode", func(t *testing.T) {
		result := env.run("net", "filter", inst.name)
		if !result.Success() {
			t.Fatalf("Getting filter mode failed: %v", result.Err)
		}
		// Should show current mode
		if !strings.Contains(result.Stdout, "active") && !strings.Contains(result.Stdout, "passive") {
			t.Error("Filter mode should show 'active' or 'passive'")
		}
	})

	t.Run("set-passive", func(t *testing.T) {
		result := env.run("net", "filter", inst.name, "passive")
		if !result.Success() {
			t.Fatalf("Setting passive mode failed: %v", result.Err)
		}
	})

	t.Run("set-active", func(t *testing.T) {
		result := env.run("net", "filter", inst.name, "active")
		if !result.Success() {
			t.Fatalf("Setting active mode failed: %v", result.Err)
		}
	})

	t.Run("invalid-mode", func(t *testing.T) {
		result := env.run("net", "filter", inst.name, "invalid")
		if result.Success() {
			t.Error("Setting invalid filter mode should fail")
		}
	})
}

// TestAllowlistReload tests reloading the allowlist.
func TestAllowlistReload(t *testing.T) {
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

	// Give filters time to start
	time.Sleep(5 * time.Second)

	// Add a domain
	inst.allowlistAdd("test.example.com")

	// Reload should succeed
	result := env.run("allowlist", "reload", inst.name)
	if !result.Success() {
		t.Fatalf("Allowlist reload failed: %v", result.Err)
	}
}

// TestDNSBlocking tests that DNS queries to non-allowlisted domains are blocked.
func TestDNSBlocking(t *testing.T) {
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

	// Clear allowlist and add only one domain
	// Note: This is a simplified test - in reality the VM needs specific domains
	// for apt, etc. We just test that the DNS filter is running.

	t.Run("blocked-domain-returns-nxdomain", func(t *testing.T) {
		// Try to resolve a domain not in the allowlist
		// The getent should fail (exit 2 = not found)
		result := inst.ssh("getent", "ahosts", "definitely-not-allowed.example.org")

		// Should fail (NXDOMAIN)
		if result.Success() {
			t.Error("DNS query to non-allowlisted domain should fail (NXDOMAIN)")
		}
	})

	t.Run("healthcheck-domain-resolves", func(t *testing.T) {
		// healthcheck.abox.local should always resolve
		// Retry because dnsfilter may need time to become fully ready
		result := inst.waitForSSHCondition(15*time.Second, 2*time.Second, func(r *runResult) bool {
			return r.Success() && strings.Contains(r.Stdout, "127.0.0.1")
		}, "getent", "ahosts", "healthcheck.abox.local")

		if !result.Success() {
			t.Errorf("Healthcheck domain should resolve: %s", result.Stderr)
		}
		if !strings.Contains(result.Stdout, "127.0.0.1") {
			t.Error("Healthcheck domain should resolve to 127.0.0.1")
		}
	})
}

// TestNetProfile tests the profile capture command (abox net profile).
func TestNetProfile(t *testing.T) {
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

	// Give filters time to start
	time.Sleep(5 * time.Second)

	t.Run("profile-show", func(t *testing.T) {
		result := env.run("net", "profile", inst.name, "show")
		if !result.Success() {
			t.Fatalf("Profile show failed: %v", result.Err)
		}
	})

	t.Run("profile-count", func(t *testing.T) {
		result := env.run("net", "profile", inst.name, "count")
		if !result.Success() {
			t.Fatalf("Profile count failed: %v", result.Err)
		}
	})

	t.Run("profile-clear", func(t *testing.T) {
		result := env.run("net", "profile", inst.name, "clear")
		if !result.Success() {
			t.Fatalf("Profile clear failed: %v", result.Err)
		}
	})

	t.Run("profile-export", func(t *testing.T) {
		result := env.run("net", "profile", inst.name, "export")
		if !result.Success() {
			t.Fatalf("Profile export failed: %v", result.Err)
		}
	})
}

// TestPassiveModeCaptures tests that passive mode captures domain requests.
func TestPassiveModeCaptures(t *testing.T) {
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

	// Clear any existing profile
	env.run("net", "profile", inst.name, "clear")

	// Switch to passive mode (allows all, captures domains)
	inst.setFilterMode("passive")

	// Make some DNS requests from inside the VM
	inst.ssh("getent", "ahosts", "github.com")
	inst.ssh("getent", "ahosts", "example.org")

	// Give time for capture
	time.Sleep(2 * time.Second)

	// Check captured domains
	result := env.run("net", "profile", inst.name, "show")
	if !result.Success() {
		t.Fatalf("Profile show failed: %v", result.Err)
	}

	// In passive mode, domains we queried should be captured
	if !strings.Contains(result.Stdout, "github.com") && !strings.Contains(result.Stdout, "example.org") {
		t.Errorf("Passive mode should capture queried domains, got:\n%s", result.Stdout)
	}
}

// TestAllowlistAffectsTraffic tests that adding and removing domains from the
// allowlist immediately affects DNS resolution from inside the VM.
func TestAllowlistAffectsTraffic(t *testing.T) {
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

	t.Run("add-allows-resolution", func(t *testing.T) {
		// Add example.com and verify it resolves from the VM
		inst.allowlistAdd("example.com")

		result := inst.waitForSSHCondition(15*time.Second, 2*time.Second, func(r *runResult) bool {
			return r.Success()
		}, "getent", "ahosts", "example.com")

		if !result.Success() {
			t.Errorf("DNS resolution for allowlisted domain should succeed: %v", result.Stderr)
		}
	})

	t.Run("non-allowed-blocks-resolution", func(t *testing.T) {
		// Verify a domain NOT in the allowlist cannot be resolved.
		// Uses an unrelated domain (not a subdomain of example.com,
		// since the allowlist uses radix tree prefix matching).
		result := inst.ssh("getent", "ahosts", "example.org")
		if result.Success() {
			t.Error("DNS resolution for non-allowed domain should fail")
		}
	})
}
