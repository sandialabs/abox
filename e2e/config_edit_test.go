//go:build e2e

package e2e

import (
	"strings"
	"testing"
	"time"
)

// TestConfigEditSubnet exercises `abox config edit --subnet`: the edit is
// rejected while the instance is running, succeeds once stopped, and takes
// effect on the next start — libvirt re-creates the network from the new
// subnet, the regenerated cloud-init (fresh instance-id per start) re-renders
// the guest's static IP, and SSH becomes reachable at the new .10 address.
func TestConfigEditSubnet(t *testing.T) {
	skipIfBackendUnavailable(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)
	if name := backendUnderTest(); name != "libvirt" {
		t.Skipf("subnet edit is libvirt-only (backend under test: %s)", name)
	}

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()

	const (
		newSubnet  = "10.77.0.0/24"
		newGuestIP = "10.77.0.10"
	)

	t.Run("rejected-while-running", func(t *testing.T) {
		env, inst := env.sub(t), inst.sub(t)
		inst.start()
		if !inst.waitForRunning(60 * time.Second) {
			t.Fatal("Instance did not start")
		}

		result := env.run("config", "edit", inst.name, "--subnet", newSubnet)
		if result.Success() {
			t.Error("config edit --subnet should fail while the instance is running")
		}
		if !strings.Contains(result.Stderr, "stop it before changing the subnet") &&
			!strings.Contains(result.Stdout, "stop it before changing the subnet") {
			t.Errorf("Expected running-instance error, got: %s %s", result.Stdout, result.Stderr)
		}

		inst.forceStop()
	})

	t.Run("edit-while-stopped", func(t *testing.T) {
		env, inst := env.sub(t), inst.sub(t)
		result := env.mustRun("config", "edit", inst.name, "--subnet", newSubnet)
		if !strings.Contains(result.Stdout, newSubnet) {
			t.Errorf("Expected change summary mentioning %s, got: %s", newSubnet, result.Stdout)
		}

		if got := inst.configValue("subnet"); got != newSubnet {
			t.Errorf("subnet = %q, want %q", got, newSubnet)
		}
		if got := inst.configValue("gateway"); got != "10.77.0.1" {
			t.Errorf("gateway = %q, want 10.77.0.1", got)
		}
		if got := inst.configValue("ip_address"); got != newGuestIP {
			t.Errorf("ip_address = %q, want %q (guest is always .10)", got, newGuestIP)
		}
	})

	t.Run("takes-effect-on-next-start", func(t *testing.T) {
		inst := inst.sub(t)
		inst.start()
		if !inst.waitForRunning(60 * time.Second) {
			t.Fatal("Instance did not start after subnet edit")
		}

		// `abox ssh` targets the configured (new) IP, so a successful probe means
		// host-to-guest reachability on the new subnet end to end.
		if !inst.waitForSSH(120 * time.Second) {
			t.Fatal("SSH did not become available at the new IP after subnet edit")
		}
		result := inst.ssh("hostname", "-I")
		if !result.Success() || !strings.Contains(result.Stdout, newGuestIP) {
			t.Errorf("Guest should hold %s after subnet edit, got: %s", newGuestIP, result.Stdout)
		}

		inst.forceStop()
	})
}
