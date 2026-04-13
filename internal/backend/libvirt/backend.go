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
	"github.com/sandialabs/abox/internal/libvirt"
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
	backend.RegisterOverrideDefault("libvirt.template", libvirt.EmbeddedDomainTemplate,
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
	traffic  *TrafficInterceptor
}

// New creates a new libvirt backend.
func New() backend.Backend {
	b := &Backend{}
	b.vm = &VMManager{}
	b.network = &NetworkManager{}
	b.disk = &DiskManager{}
	b.snapshot = &SnapshotManager{}
	b.traffic = &TrafficInterceptor{}
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

// TrafficInterceptor returns the traffic interceptor.
func (b *Backend) TrafficInterceptor() backend.TrafficInterceptor {
	return b.traffic
}

// DryRun outputs the libvirt XML configuration that would be created for an instance.
func (b *Backend) DryRun(inst *config.Instance, paths *config.Paths, w io.Writer, opts backend.VMCreateOptions) error {
	fmt.Fprintln(w, "=== Domain XML ===")
	domainXML, err := libvirt.DomainXMLWithOptions(inst, paths, libvirt.DomainXMLOptions{
		AssumeCloudInitExists: true,
		CustomTemplate:        opts.CustomTemplate,
	})
	if err != nil {
		return fmt.Errorf("failed to generate domain XML: %w", err)
	}
	fmt.Fprintln(w, domainXML)

	fmt.Fprintln(w, "\n=== Network XML ===")
	networkXML, err := libvirt.NetworkXML(inst)
	if err != nil {
		return fmt.Errorf("failed to generate network XML: %w", err)
	}
	fmt.Fprintln(w, networkXML)

	fmt.Fprintln(w, "\n=== NWFilter XML ===")
	nwfilterXML, err := libvirt.NWFilterXML(inst, "")
	if err != nil {
		return fmt.Errorf("failed to generate nwfilter XML: %w", err)
	}
	fmt.Fprintln(w, nwfilterXML)

	return nil
}

// ResourceNames returns the standardized resource names for an instance.
// Libvirt uses "abox-<name>" prefix for domains/networks and "abox-<name>-traffic" for filters.
func (b *Backend) ResourceNames(instanceName string) backend.ResourceNames {
	return backend.ResourceNames{
		Instance: instanceName,
		VM:       "abox-" + instanceName,
		Network:  config.GenerateBridgeName(instanceName),
		Filter:   "abox-" + instanceName + "-traffic",
	}
}

// GenerateMAC returns a new random MAC address with the libvirt OUI prefix (52:54:00).
func (b *Backend) GenerateMAC() string {
	return libvirt.GenerateMAC()
}

// StorageDir returns the root directory for libvirt disk images.
// This is /var/lib/libvirt/images/abox, which is accessible by the
// libvirt-qemu user and requires elevated privileges to manage.
func (b *Backend) StorageDir() string {
	return config.LibvirtImagesDir
}

// ValidateCustomTemplate validates a domain XML template by parsing it and executing
// with zero-value data to catch syntax errors and invalid field references.
func (b *Backend) ValidateCustomTemplate(content string) error {
	return libvirt.ValidateTemplate(content)
}

// HasCustomTemplate reports whether a custom domain template is stored for this instance.
func (b *Backend) HasCustomTemplate(inst *config.Instance) bool {
	v, ok := inst.BackendConfig["custom_template"]
	if !ok {
		return false
	}
	b2, _ := v.(bool)
	return b2
}

// SetCustomTemplate marks the instance config as having (or not having) a custom template.
func (b *Backend) SetCustomTemplate(inst *config.Instance, has bool) {
	if inst.BackendConfig == nil {
		inst.BackendConfig = make(map[string]any)
	}
	inst.BackendConfig["custom_template"] = has
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
