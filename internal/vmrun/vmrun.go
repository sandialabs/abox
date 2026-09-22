// Package vmrun provides portable helpers shared by the VMware Workstation/
// Fusion backend. It contains only platform-neutral code (no OS build tag) so it
// compiles on Linux, macOS, and Windows.
package vmrun

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strings"

	"github.com/sandialabs/abox/internal/validation"
)

// runCommand is the seam through which all vmrun invocations pass. Tests swap it
// via SetRunCommandForTest so no real vmrun binary is ever executed. It mirrors
// the override-var style used elsewhere (e.g. qemuimg.SetRunCmdForTest).
var runCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// SetRunCommandForTest replaces the command runner and returns a restore func.
// Test-only helper.
func SetRunCommandForTest(fn func(ctx context.Context, name string, args ...string) ([]byte, error)) func() {
	prev := runCommand
	runCommand = fn
	return func() { runCommand = prev }
}

// envVmrunHostType overrides the vmrun host driver for nonstandard setups (e.g.
// "player"). Unset in the common case; the GOOS default is correct for Fusion and
// Workstation.
const envVmrunHostType = "ABOX_VMRUN_HOSTTYPE"

// vmrunHostType selects the vmrun host driver: "fusion" on macOS, "ws" elsewhere.
// The GOOS default comes from hostTypeDefault (build-tagged in hosttype_*.go). A
// hardcoded "ws" (the previous behavior) makes every vmrun call fail on Fusion,
// since Fusion's vmrun expects "-T fusion". ABOX_VMRUN_HOSTTYPE overrides for
// nonstandard hosts.
func vmrunHostType() string {
	if v := os.Getenv(envVmrunHostType); v != "" {
		return v
	}
	return hostTypeDefault()
}

// vmrun invokes the vmrun CLI with the shared "-T <hostType>" prefix and returns
// its combined output. Errors wrap the command output like the qemuimg helpers,
// so callers surface vmrun's own diagnostics.
func vmrun(ctx context.Context, args ...string) ([]byte, error) {
	full := append([]string{"-T", vmrunHostType()}, args...)
	out, err := runCommand(ctx, "vmrun", full...)
	if err != nil {
		return out, fmt.Errorf("vmrun %s failed: %w: %s",
			strings.Join(full, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// Start powers on the VM defined by vmx (headless). vmrun: start <vmx> nogui.
func Start(ctx context.Context, vmx string) error {
	_, err := vmrun(ctx, "start", vmx, "nogui")
	return err
}

// Stop gracefully powers off the VM. vmrun: stop <vmx> soft.
func Stop(ctx context.Context, vmx string) error {
	_, err := vmrun(ctx, "stop", vmx, "soft")
	return err
}

// ForceStop hard-powers off the VM. vmrun: stop <vmx> hard.
func ForceStop(ctx context.Context, vmx string) error {
	_, err := vmrun(ctx, "stop", vmx, "hard")
	return err
}

// DeleteVM deletes the VM defined by vmx. vmrun: deleteVM <vmx>.
func DeleteVM(ctx context.Context, vmx string) error {
	_, err := vmrun(ctx, "deleteVM", vmx)
	return err
}

// ListRunning returns the .vmx paths of all currently running VMs. vmrun: list.
// The output is a header line ("Total running VMs: N") followed by one vmx path
// per line; the header is skipped and blank lines ignored.
func ListRunning(ctx context.Context) ([]string, error) {
	out, err := vmrun(ctx, "list")
	if err != nil {
		return nil, err
	}
	var paths []string
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Total running VMs:") {
			continue
		}
		paths = append(paths, line)
	}
	return paths, nil
}

// CreateSnapshot takes a snapshot of the VM. vmrun: snapshot <vmx> <name>.
// The name is validated (rejecting a leading '-' and shell/flag metacharacters)
// before it reaches vmrun as a trailing positional, so a crafted snapshot name
// cannot be interpreted as a vmrun flag. vmrun does not accept a "--" separator,
// so ValidateSnapshotName's regex is the protection.
func CreateSnapshot(ctx context.Context, vmx, name string) error {
	if err := validation.ValidateSnapshotName(name); err != nil {
		return err
	}
	_, err := vmrun(ctx, "snapshot", vmx, name)
	return err
}

// ListSnapshots returns the snapshot names for the VM. vmrun: listSnapshots
// <vmx>. The output is a header line ("Total snapshots: N") followed by one name
// per line; the header is skipped and blank lines ignored.
func ListSnapshots(ctx context.Context, vmx string) ([]string, error) {
	out, err := vmrun(ctx, "listSnapshots", vmx)
	if err != nil {
		return nil, err
	}
	var names []string
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Total snapshots:") {
			continue
		}
		names = append(names, line)
	}
	return names, nil
}

// RevertToSnapshot reverts the VM to a snapshot. vmrun: revertToSnapshot <vmx>
// <name>. The name is validated (see CreateSnapshot): the revert path does not
// otherwise validate, so a snapshot created out-of-band (VMware GUI / crafted
// .vmsd) named "--"/"-h"/etc. could be handed to vmrun as a flag.
func RevertToSnapshot(ctx context.Context, vmx, name string) error {
	if err := validation.ValidateSnapshotName(name); err != nil {
		return err
	}
	_, err := vmrun(ctx, "revertToSnapshot", vmx, name)
	return err
}

// DeleteSnapshot deletes a snapshot. vmrun: deleteSnapshot <vmx> <name>. The name
// is validated (see RevertToSnapshot) so an out-of-band snapshot name cannot be
// interpreted as a vmrun flag.
func DeleteSnapshot(ctx context.Context, vmx, name string) error {
	if err := validation.ValidateSnapshotName(name); err != nil {
		return err
	}
	_, err := vmrun(ctx, "deleteSnapshot", vmx, name)
	return err
}

// GenerateMAC generates a random MAC address with the VMware OUI prefix.
// Uses VMware's registered OUI 00:0c:29, matching the addresses vmware assigns
// to guest NICs. Go 1.20+ auto-seeds the global rand, so no manual seeding
// needed. Mirrors internal/virsh.GenerateMAC's style (math/rand is fine; a
// MAC address does not need cryptographic randomness).
func GenerateMAC() string {
	return fmt.Sprintf("00:0c:29:%02x:%02x:%02x",
		rand.Intn(256), rand.Intn(256), rand.Intn(256)) //nolint:gosec // MAC address doesn't need crypto randomness
}
