// Package vmware implements the backend interface for VMware Workstation/Fusion.
//
// This package is portable: it carries no OS build tag and must compile on
// Linux, macOS, and Windows. VMware Workstation runs on Linux/Windows and
// Fusion runs on macOS, all driven through the vmrun CLI.
//
// EXPERIMENTAL: the backend compiles and is unit-tested, but has not been
// validated end-to-end on a real VMware host (see the TODO(real-host) markers in
// this package and internal/vmrun). It is registered as experimental, so it is
// never chosen by silent auto-detection and must be selected explicitly via
// ABOX_BACKEND=vmware.
package vmware

import (
	"fmt"
	"io"
	"os/exec"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/vmrun"
)

const (
	// Name is the identifier for this backend.
	Name = "vmware"

	// Priority determines auto-detection order. Lower is tried first.
	// vmware sits below libvirt (10) so libvirt stays the auto-detect default
	// on Linux. It is experimental and never chosen by auto-detection on any
	// platform (macOS auto-detects the vfkit backend); it is reached only when
	// selected explicitly via ABOX_BACKEND=vmware.
	Priority = 20

	// vmrunBinary is the VMware CLI that drives every operation (shipped with
	// Workstation/Fusion).
	vmrunBinary = "vmrun"
)

func init() {
	// Experimental: never auto-selected; reachable only via ABOX_BACKEND=vmware
	// until validated on a real VMware host.
	backend.RegisterExperimental(Name, Priority, New)
}

// Backend implements the backend.Backend interface for VMware.
type Backend struct {
	vm       *VMManager
	network  *NetworkManager
	disk     *DiskManager
	snapshot *SnapshotManager
	egress   *EgressController
}

// New creates a new vmware backend.
func New() backend.Backend {
	return &Backend{
		vm:       &VMManager{},
		network:  &NetworkManager{},
		disk:     &DiskManager{},
		snapshot: &SnapshotManager{},
		egress:   &EgressController{},
	}
}

// Name returns the backend identifier.
func (b *Backend) Name() string {
	return Name
}

// IsAvailable checks if VMware is available on this system by looking for the
// vmrun CLI (shipped with Workstation/Fusion), mirroring libvirt's virsh check.
func (b *Backend) IsAvailable() error {
	if _, err := exec.LookPath(vmrunBinary); err != nil {
		return err
	}
	return nil
}

// RequiredTools declares the host binaries only the vmware backend needs
// (beyond abox's common toolset). vmrun drives all VMware operations. The
// host-only network tool is NOT declared here because on macOS Fusion it lives
// inside the .app (not on PATH), which the PATH-based check would misreport;
// checkdeps resolves it (and runs a vmrun functional probe) via a dedicated
// VMware preflight instead. Implements backend.ToolRequirer.
func (b *Backend) RequiredTools() []backend.Tool {
	return []backend.Tool{
		{Name: vmrunBinary, UsedBy: "experimental VMware backend only (ABOX_BACKEND=vmware); not needed for libvirt",
			Hint: "install VMware Workstation Pro or Fusion (provides vmrun)"},
	}
}

// VM returns the VM manager.
func (b *Backend) VM() backend.VMManager {
	return b.vm
}

// Network returns the network manager.
func (b *Backend) Network() backend.NetworkManager {
	return b.network
}

// Disk returns the disk manager.
func (b *Backend) Disk() backend.DiskManager {
	return b.disk
}

// Snapshot returns the snapshot manager (vmrun-backed).
func (b *Backend) Snapshot() backend.SnapshotManager {
	return b.snapshot
}

// EgressController returns the egress controller. It installs the host-side
// enforcement (DNS REDIRECT + filter-port accepts + a per-bridge default-deny) on
// the instance's vmnet, which — combined with the host-only topology's lack of an
// uplink — confines the guest to the same egress guarantee as libvirt.
func (b *Backend) EgressController() backend.EgressController {
	return b.egress
}

// monitorGuestDevice is the in-guest device the monitor agent writes Tetragon
// events to. VMware has no virtio-serial, so monitoring rides a serial pipe
// (see internal/vmrun.vmxTemplate serial0 block), which the guest sees as
// /dev/ttyS0. Must match the serial index chosen in the .vmx template.
const monitorGuestDevice = "/dev/ttyS0"

// vmwareMonitorTransport carries monitoring over a serial pipe bound to the
// instance's monitor socket.
type vmwareMonitorTransport struct{}

// GuestDevice returns the serial tty path inside the guest.
func (vmwareMonitorTransport) GuestDevice() string { return monitorGuestDevice }

// MonitorTransport returns the VMware monitor transport. The .vmx serial0 pipe
// (endPoint=server) makes VMware listen on the instance's monitor socket at
// power-on; the host daemon dials it just as it does for libvirt.
func (b *Backend) MonitorTransport() backend.MonitorTransport {
	return vmwareMonitorTransport{}
}

// DryRun outputs the backend-specific configuration that would be created for an
// instance without creating any resources. It emits the generated .vmx (with the
// cloud-init CDROM assumed present, as it would be at real create time).
func (b *Backend) DryRun(inst *config.Instance, paths *config.Paths, w io.Writer, opts backend.VMCreateOptions) error {
	opts.AssumeCloudInitExists = true
	vmx, err := vmrun.GenerateVMX(inst, paths, toVMXOptions(opts))
	if err != nil {
		return fmt.Errorf("failed to generate vmx: %w", err)
	}
	fmt.Fprintln(w, "=== VMX ===")
	fmt.Fprint(w, vmx)
	return nil
}

// ResourceNames returns the standardized resource names for an instance.
func (b *Backend) ResourceNames(instanceName string) backend.ResourceNames {
	return backend.ResourceNames{
		Instance: instanceName,
		VM:       "abox-" + instanceName,
		Network:  config.GenerateBridgeName(instanceName),
	}
}

// GenerateMAC returns a new random MAC address with the VMware OUI prefix.
func (b *Backend) GenerateMAC() string {
	return vmrun.GenerateMAC()
}

// StorageDir returns the root directory for backend-managed disk images.
func (b *Backend) StorageDir() string {
	return config.UserStorageDir()
}
