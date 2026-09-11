//go:build e2e

package e2e

import (
	"strings"
	"testing"
	"time"
)

// TestVMwareSmoke is a focused, single-pass smoke test for the experimental
// vmware backend. The parametrized e2e suite (lifecycle/security/etc.) already
// covers breadth across whichever backend is selected via ABOX_BACKEND; this
// test exists to give the vmware backend one deliberate, self-contained
// end-to-end pass that exercises its security-critical seams together:
//
//   - create -> start -> instance reachable/running (VM + host-only network up),
//   - egress default-deny is ENFORCED: the guest cannot reach the internet
//     directly, validating the host-side FORWARD deny for vmnets plus the
//     no-uplink host-only isolation,
//   - stop -> remove clean teardown.
//
// It is a SMOKE test (one representative flow), not an exhaustive matrix.
//
// SKIP GUARD:
//   - It runs ONLY when the operator has explicitly selected the vmware backend
//     (ABOX_BACKEND=vmware, surfaced via backendUnderTest()). On the normal
//     libvirt CI and in developer environments where the default backend is in
//     effect, backendUnderTest() != "vmware" and the test cleanly SKIPs.
//   - Even with vmware selected, it additionally requires vmware to be usable on
//     the host. That check is delegated to skipIfBackendUnavailable(t), which
//     resolves the selected backend and defers to its own IsAvailable() (the
//     vmware backend probes for the VMware CLI). No detection logic is
//     duplicated here.
//
// Because no live VMware host is available in CI or the dev sandbox, this test
// is guaranteed to SKIP there; it only executes against a real VMware host.
func TestVMwareSmoke(t *testing.T) {
	// Gate 1: only run when vmware is the explicitly selected backend. This keeps
	// the smoke test dormant on the default (libvirt) path.
	if backendUnderTest() != "vmware" {
		t.Skip("vmware smoke test only runs with ABOX_BACKEND=vmware")
	}

	// Gate 2: vmware must actually be available/usable on this host. Reuses the
	// shared guard, which defers to the vmware backend's IsAvailable() and skips
	// cleanly when the backend is unusable (e.g. no VMware CLI installed).
	skipIfBackendUnavailable(t)

	// The configured base image must be present for the selected backend.
	skipIfNoConfiguredBaseImage(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()

	// create -> start (Cleanup registered by newTestInstance handles teardown even
	// on failure; we still assert an explicit stop/remove at the end).
	inst.create()
	inst.start()

	if !inst.waitForRunning(60 * time.Second) {
		t.Fatal("vmware instance did not reach running state")
	}

	if !inst.waitForSSH(120 * time.Second) {
		t.Fatal("SSH did not become available on vmware instance")
	}

	// Core security seam: egress default-deny must be ENFORCED. Mirrors
	// security_test.go's TestNetworkBlocksDirectAccess — a direct ping to a public
	// IP must fail because the host-side FORWARD deny for the vmnet plus the
	// no-uplink host-only network leave the guest with no direct route to the
	// internet. Filtered egress is only permitted through the proxy.
	inst.setFilterMode("active")

	result := inst.ssh("ping", "-c", "1", "-W", "5", "8.8.8.8")
	if result.Success() {
		t.Error("direct ping to 8.8.8.8 succeeded - vmware egress default-deny " +
			"(host FORWARD deny + host-only isolation) should block direct access")
	}

	// stop -> remove: explicit clean teardown of the representative pass.
	inst.forceStop()

	status := inst.status()
	if vmStatePattern.MatchString(status) {
		t.Errorf("vmware instance should not be running after stop, status: %s", status)
	}

	inst.remove()

	if listResult := env.run("list"); strings.Contains(listResult.Stdout, inst.name) {
		t.Errorf("vmware instance %s should not appear in list after remove", inst.name)
	}
}
