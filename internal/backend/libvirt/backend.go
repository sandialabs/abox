//go:build linux

// Package libvirt implements the backend interface for libvirt/QEMU/KVM on Linux.
package libvirt

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/virsh"
)

const (
	// Name is the identifier for this backend.
	Name = "libvirt"

	// Priority determines auto-detection order. Lower is tried first.
	// libvirt is the primary backend on Linux, so it has highest priority.
	Priority = 10
)

func init() {
	backend.Register(Name, Priority, New)
	backend.RegisterOverrideDefault("libvirt.template", virsh.EmbeddedDomainTemplate,
		`Libvirt domain XML template for defining VMs (Go text/template).
Variables: {{.Name}}, {{.UUID}}, {{.Memory}}, {{.CPUs}}, {{.NetQueues}},
{{.DiskPath}}, {{.CloudInitISO}}, {{.MACAddress}}, {{.Bridge}},
{{.MonitorSocket}}, {{.MonitorSocketUID}}, {{.MonitorSocketGID}}`)
}

// Backend implements the backend.Backend interface for libvirt.
type Backend struct {
	vm       *VMManager
	network  *NetworkManager
	disk     *DiskManager
	snapshot *SnapshotManager
	egress   *EgressController
}

// New creates a new libvirt backend.
func New() backend.Backend {
	b := &Backend{}
	b.vm = &VMManager{}
	b.network = &NetworkManager{}
	b.disk = &DiskManager{}
	b.snapshot = &SnapshotManager{}
	b.egress = &EgressController{}
	return b
}

// Name returns the backend identifier.
func (b *Backend) Name() string {
	return Name
}

// IsAvailable checks if libvirt is available on this system.
func (b *Backend) IsAvailable() error {
	// Check if virsh command exists
	if _, err := exec.LookPath("virsh"); err != nil {
		return err
	}
	return nil
}

// RequiredTools declares the host binaries only the libvirt backend needs
// (beyond abox's common toolset). virsh drives all libvirt operations. The QEMU
// runtime user reaches disk images via group ownership of the per-user storage
// root (see internal/backend/libvirt/disk.go and the privilege helper's
// EnsureStorageRoot), so no ACL tooling is required. Implements
// backend.ToolRequirer.
func (b *Backend) RequiredTools() []backend.Tool {
	return []backend.Tool{
		{Name: "virsh", UsedBy: "all VM/network operations",
			Hint: "install libvirt-clients (Debian/Ubuntu) or libvirt-client (Fedora/RHEL/Arch)"},
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

// Snapshot returns the snapshot manager.
func (b *Backend) Snapshot() backend.SnapshotManager {
	return b.snapshot
}

// EgressController returns the egress controller.
func (b *Backend) EgressController() backend.EgressController {
	return b.egress
}

// SetEgressProvider injects the privileged enforcer provider used by the egress
// controller to install host-side rules (iptables DNS REDIRECT + INPUT accepts).
// Called by the factory after construction; satisfies backend.EgressProviderSetter.
func (b *Backend) SetEgressProvider(p backend.EgressEnforcerProvider) {
	b.egress.Provider = p
}

// monitorGuestDevice is the in-guest path of the virtio-serial port the monitor
// agent writes Tetragon events to. It corresponds to the channel target name
// (abox.monitor.0) declared in the domain template (domain.xml.tmpl).
const monitorGuestDevice = "/dev/virtio-ports/abox.monitor.0"

// libvirtMonitorTransport carries monitoring over a virtio-serial channel.
type libvirtMonitorTransport struct{}

// GuestDevice returns the virtio-serial port path inside the guest.
func (libvirtMonitorTransport) GuestDevice() string { return monitorGuestDevice }

// MonitorTransport returns the libvirt monitor transport. Events travel over a
// virtio-serial channel bound to the instance's monitor socket (wired by the
// domain template when MonitorEnabled); the host daemon reads that socket.
func (b *Backend) MonitorTransport() backend.MonitorTransport {
	return libvirtMonitorTransport{}
}

// DryRun outputs the libvirt XML configuration that would be created for an instance.
func (b *Backend) DryRun(inst *config.Instance, paths *config.Paths, w io.Writer, opts backend.VMCreateOptions) error {
	fmt.Fprintln(w, "=== Domain XML ===")
	domainXML, err := virsh.DomainXMLWithOptions(inst, paths, virsh.DomainXMLOptions{
		AssumeCloudInitExists: true,
		CustomTemplate:        opts.CustomTemplate,
	})
	if err != nil {
		return fmt.Errorf("failed to generate domain XML: %w", err)
	}
	fmt.Fprintln(w, domainXML)

	fmt.Fprintln(w, "\n=== Network XML ===")
	networkXML, err := virsh.NetworkXML(inst)
	if err != nil {
		return fmt.Errorf("failed to generate network XML: %w", err)
	}
	fmt.Fprintln(w, networkXML)

	fmt.Fprintln(w, "\n=== NWFilter XML ===")
	p := backend.BuildEgressPolicy(inst)
	nwfilterXML, err := virsh.NWFilterXML(inst, "", p.GuestDNSPort)
	if err != nil {
		return fmt.Errorf("failed to generate nwfilter XML: %w", err)
	}
	fmt.Fprintln(w, nwfilterXML)

	return nil
}

// ResourceNames returns the standardized resource names for an instance.
// Libvirt uses "abox-<name>" prefix for domains/networks. The nwfilter name is
// owned by the egress controller (see filterName).
func (b *Backend) ResourceNames(instanceName string) backend.ResourceNames {
	return backend.ResourceNames{
		Instance: instanceName,
		VM:       "abox-" + instanceName,
		Network:  config.GenerateBridgeName(instanceName),
	}
}

// GenerateMAC returns a new random MAC address with the libvirt OUI prefix (52:54:00).
func (b *Backend) GenerateMAC() string {
	return virsh.GenerateMAC()
}

// StorageDir returns the root directory for this user's libvirt disk images:
// the per-user subtree /var/lib/libvirt/images/abox/<uid>. It is reachable and
// readable by the libvirt-qemu runtime user via group ownership (no ACLs, no
// $HOME traversal). Per-instance disk operations run unprivileged as the calling
// user; only the one-time root provisioning uses the privilege helper (see
// SetStorageProvider / DiskManager.ensureStorageRoot).
func (b *Backend) StorageDir() string {
	return config.LibvirtStorageDir()
}

// SetStorageProvider injects the privileged storage enforcer provider used by
// the disk manager to provision the per-user storage root. Called by the factory
// after construction; satisfies backend.StorageProviderSetter.
func (b *Backend) SetStorageProvider(p backend.StorageEnforcerProvider) {
	b.disk.storageProvider = p
}

// ValidateCustomTemplate validates a domain XML template by parsing it and executing
// with zero-value data to catch syntax errors and invalid field references.
func (b *Backend) ValidateCustomTemplate(content string) error {
	return virsh.ValidateTemplate(content)
}

// HasCustomTemplate reports whether a custom domain template is stored for this instance.
func (b *Backend) HasCustomTemplate(inst *config.Instance) bool {
	has, _ := inst.BackendBool(config.BackendKeyCustomTemplate)
	return has
}

// SetCustomTemplate marks the instance config as having (or not having) a custom template.
func (b *Backend) SetCustomTemplate(inst *config.Instance, has bool) {
	if inst.BackendConfig == nil {
		inst.BackendConfig = make(map[string]any)
	}
	inst.BackendConfig[config.BackendKeyCustomTemplate] = has
}

// templatePath returns the path where the custom domain template is stored for this instance.
func templatePath(paths *config.Paths) string {
	return filepath.Join(paths.Instance, "domain.xml.tmpl")
}

// LoadCustomTemplate reads the stored custom domain template for this instance.
func (b *Backend) LoadCustomTemplate(paths *config.Paths) (string, error) {
	p := templatePath(paths)
	content, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("custom domain template not found at %s; re-create the instance to restore it", p)
		}
		return "", fmt.Errorf("failed to read custom domain template: %w", err)
	}
	return string(content), nil
}

// StoreCustomTemplate writes a custom domain template to the instance's data directory.
func (b *Backend) StoreCustomTemplate(paths *config.Paths, content string) error {
	if err := os.WriteFile(templatePath(paths), []byte(content), 0o600); err != nil {
		return fmt.Errorf("failed to write custom template: %w", err)
	}
	return nil
}
