package cloudinit

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/validation"
)

// isoFileMode is the cloud-init ISO mode: owner rw, group r (the QEMU process
// reads it via the group inherited from the setgid storage dir), no others.
const isoFileMode = 0o640

// subnetPrefix returns the prefix length (e.g. 24) of an instance's subnet CIDR
// so the guest's static address can be written as "<ip>/<prefix>".
func subnetPrefix(subnet string) (int, error) {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return 0, fmt.Errorf("invalid instance subnet %q: %w", subnet, err)
	}
	ones, _ := ipnet.Mask.Size()
	return ones, nil
}

// GenerateAndInstall creates a cloud-init ISO directly in the instance's storage
// directory. It runs unprivileged; the ISO inherits the QEMU runtime group from
// the setgid storage tree (see internal/backend/libvirt/disk.go), so the VM
// process can read it at boot without ACLs. (The libvirt disk manager's
// EnsureAccess re-asserts these modes before boot as a backstop.)
func GenerateAndInstall(inst *config.Instance, paths *config.Paths, contributors []Contributor) error {
	// Read the SSH public key
	pubKeyPath := paths.SSHKey + ".pub"
	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read SSH public key: %w", err)
	}
	pubKey := strings.TrimSpace(string(pubKeyBytes))

	// Validate SSH public key format
	if err := validation.ValidateSSHPublicKey(pubKey); err != nil {
		return fmt.Errorf("invalid SSH public key: %w", err)
	}

	// Derive the subnet prefix for the guest's static address from the instance
	// subnet (a /24 today, but parse it so the two can't silently drift).
	prefix, err := subnetPrefix(inst.Subnet)
	if err != nil {
		return err
	}

	// Create cloud-init config
	cfg := &Config{
		Hostname:     inst.Name,
		Username:     inst.GetUser(),
		SSHPublicKey: pubKey,
		MACAddress:   inst.MACAddress,
		IPAddress:    inst.IPAddress,
		Gateway:      inst.Gateway,
		Prefix:       prefix,
		Contributors: contributors,
	}

	// Ensure the destination directory exists. In the libvirt storage tree this
	// dir was already created setgid by the disk manager, so the ISO inherits the
	// QEMU group; this MkdirAll is a defensive no-op in that case.
	dir := filepath.Dir(paths.CloudInitISO)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("failed to create cloud-init ISO directory: %w", err)
	}

	// Build into a temp file in the SAME directory, then atomically rename over
	// the destination. Rationale: a previous VM start may have left the existing
	// ISO owned by the QEMU runtime user (libvirtd dynamic_ownership=1 chowns the
	// readonly CDROM source at boot and does not restore it on stop), so
	// regenerating in place fails — genisoimage cannot truncate a file the caller
	// no longer owns. os.CreateTemp makes an exclusively-created regular file
	// (never a pre-planted symlink) that inherits the QEMU group from the setgid
	// dir; os.Rename then replaces the destination atomically. Rename needs write
	// on the parent dir (the caller owns it), NOT ownership of the dest, and
	// overwrites a symlink at the dest rather than following it — so it clears the
	// libvirt-owned file and any tampering in one syscall, and a failed generation
	// leaves the previous (still valid) ISO in place. Same-directory keeps the
	// rename on one filesystem, which is what makes it atomic.
	tmp, err := os.CreateTemp(dir, "cidata-*.iso")
	if err != nil {
		return fmt.Errorf("failed to create temp cloud-init ISO: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	// Cleans up the temp on any early return; a no-op once the rename moves it.
	defer func() { _ = os.Remove(tmpPath) }()

	if err := CreateISO(tmpPath, cfg); err != nil {
		return err
	}

	// Group-readable so the QEMU process can attach the ISO at VM start (the group
	// is inherited from the setgid storage dir; no ACLs needed). Chmod the temp
	// before the rename so the final file appears atomically with its mode set. No
	// symlink guard is needed: os.CreateTemp created this regular file exclusively.
	if err := os.Chmod(tmpPath, isoFileMode); err != nil {
		return fmt.Errorf("failed to set cloud-init ISO permissions: %w", err)
	}
	if err := os.Rename(tmpPath, paths.CloudInitISO); err != nil {
		return fmt.Errorf("failed to install cloud-init ISO: %w", err)
	}

	return nil
}
