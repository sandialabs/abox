package vmware

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/timeout"
	"github.com/sandialabs/abox/internal/vmrun"
)

// VMManager implements backend.VMManager for VMware.
//
// A VMware VM is "defined" simply by its .vmx file existing on disk (there is no
// central registry to define into, unlike libvirt's virsh define). So Create just
// writes the .vmx; lifecycle operations resolve the .vmx from the instance name
// via config.Load (which honors the instance's persisted StorageDir) and shell
// to vmrun.
type VMManager struct{}

// vmxPathFor resolves the .vmx path for an instance name. VMManager lifecycle
// methods receive only the name, so the path is derived here from the instance's
// PERSISTED storage: config.Load returns *Paths honoring inst.StorageDir (which
// may differ from the default — legacy libvirt-images-dir instances or a custom
// storage root). Using config.GetPaths here would always resolve to the default
// storage dir and miss the .vmx that Create wrote under the persisted one.
//
// config.Load returns an error if the instance/config is missing. The bool
// methods (Exists/IsRunning/State) treat that as "not present"; the ctx methods
// return the wrapped error.
func vmxPathFor(name string) (string, error) {
	_, paths, err := config.Load(name)
	if err != nil {
		return "", err
	}
	return vmrun.VMXPath(paths), nil
}

// toVMXOptions copies backend options into the portable vmrun.VMXOptions
// (the vmware package cannot import backend without a cycle).
func toVMXOptions(opts backend.VMCreateOptions) vmrun.VMXOptions {
	return vmrun.VMXOptions{
		AssumeCloudInitExists: opts.AssumeCloudInitExists,
		MonitorEnabled:        opts.MonitorEnabled,
		UUID:                  opts.UUID,
	}
}

// Create defines a new VM by generating and writing its .vmx. No vmrun call is
// needed — VMware "registers" a VM implicitly by the .vmx existing.
func (m *VMManager) Create(ctx context.Context, inst *config.Instance, paths *config.Paths, opts backend.VMCreateOptions) error {
	if err := os.MkdirAll(paths.DiskDir, 0o700); err != nil {
		return fmt.Errorf("failed to create disk directory: %w", err)
	}

	vmx, err := vmrun.GenerateVMX(inst, paths, toVMXOptions(opts))
	if err != nil {
		return fmt.Errorf("failed to generate vmx: %w", err)
	}

	if err := os.WriteFile(vmrun.VMXPath(paths), []byte(vmx), 0o600); err != nil {
		return fmt.Errorf("failed to write vmx: %w", err)
	}
	return nil
}

// Redefine regenerates the .vmx, preserving the VM UUID so its identity is stable
// across the rewrite (mirrors libvirt's Redefine). If no UUID is supplied the
// current one is read from the existing .vmx.
func (m *VMManager) Redefine(ctx context.Context, inst *config.Instance, paths *config.Paths, opts backend.VMCreateOptions) error {
	if opts.UUID == "" {
		opts.UUID = m.GetUUID(inst.Name)
	}
	return m.Create(ctx, inst, paths, opts)
}

// Start powers on the VM.
//
// When monitoring is enabled, a stale monitor socket from a previous run is
// cleared first: the .vmx binds serial0 as a pipe SERVER at that path, and
// VMware fails to create the listener if the socket file already exists. The
// monitor daemon (spawned before this call) tolerates the brief window — it
// reconnects on EOF, so if it dialed the stale socket it recovers once VMware
// recreates it at power-on.
func (m *VMManager) Start(ctx context.Context, name string) error {
	inst, paths, err := config.Load(name)
	if err != nil {
		return err
	}
	if inst.Monitor.Enabled {
		if err := removeStaleMonitorSocket(paths.MonitorSocket); err != nil {
			return fmt.Errorf("failed to remove stale monitor socket: %w", err)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout.Default)
	defer cancel()
	return vmrun.Start(ctx, vmrun.VMXPath(paths))
}

// removeStaleMonitorSocket clears a leftover monitor socket so VMware's
// serial-pipe server bind does not fail on it. It removes ONLY a socket: a
// missing path is fine, and a non-socket (regular file, symlink, dir) is left
// untouched so we never silently delete unexpected data — VMware's bind then
// fails loudly instead.
func removeStaleMonitorSocket(socketPath string) error {
	info, err := os.Lstat(socketPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return nil
	}
	return os.Remove(socketPath)
}

// Stop gracefully powers off the VM.
func (m *VMManager) Stop(ctx context.Context, name string) error {
	vmx, err := vmxPathFor(name)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout.Default)
	defer cancel()
	return vmrun.Stop(ctx, vmx)
}

// ForceStop hard-powers off the VM.
func (m *VMManager) ForceStop(ctx context.Context, name string) error {
	vmx, err := vmxPathFor(name)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout.Default)
	defer cancel()
	return vmrun.ForceStop(ctx, vmx)
}

// Remove deletes the VM definition. It best-effort calls vmrun deleteVM (ignoring
// a "not found" style failure for a VM that was never registered/started) and
// then ensures the .vmx file is gone. It does NOT delete the rest of DiskDir —
// that is DiskManager.Delete's job (matching libvirt's separation).
func (m *VMManager) Remove(ctx context.Context, name string) error {
	vmx, err := vmxPathFor(name)
	if err != nil {
		// A partial teardown may have removed config.yaml while leaving the .vmx
		// behind. Fall back to the standard path layout (derived from the name only)
		// so Remove can still clean up the leftover instead of erroring forever.
		paths, perr := config.GetPaths(name)
		if perr != nil {
			return err
		}
		vmx = vmrun.VMXPath(paths)
	}

	dctx, cancel := context.WithTimeout(ctx, timeout.Default)
	defer cancel()
	// Best-effort: a VM that was never powered on has no vmrun-side registration,
	// so deleteVM may fail; that is not an error for Remove.
	_ = vmrun.DeleteVM(dctx, vmx)

	if err := os.Remove(vmx); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove vmx: %w", err)
	}
	return nil
}

// Exists reports whether the VM is defined (its .vmx file exists).
func (m *VMManager) Exists(name string) bool {
	vmx, err := vmxPathFor(name)
	if err != nil {
		return false
	}
	_, err = os.Stat(vmx)
	return err == nil
}

// IsRunning reports whether the instance's .vmx is among the running VMs.
func (m *VMManager) IsRunning(name string) bool {
	vmx, err := vmxPathFor(name)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout.Default)
	defer cancel()
	running, err := vmrun.ListRunning(ctx)
	if err != nil {
		return false
	}
	// Normalize both sides so a benign path difference (trailing "..", redundant
	// separators, or a symlinked component) between our derived path and vmrun's
	// reported path doesn't cause a false negative. EvalSymlinks resolves symlinks
	// where the file exists on this host; if it fails (e.g. vmrun reports a path
	// that doesn't resolve locally) fall back to the lexically-cleaned form.
	want := resolvePath(vmx)
	for _, r := range running {
		if resolvePath(r) == want {
			return true
		}
	}
	return false
}

// resolvePath returns a canonical form of p for comparison: EvalSymlinks when it
// succeeds, otherwise filepath.Clean. Portable (filepath only).
func resolvePath(p string) string {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	return filepath.Clean(p)
}

// State returns the VM state. vmrun exposes only running/not-running, so the
// mapping is coarse: running -> Running; defined-but-not-running -> Stopped;
// not defined -> Unknown. (No paused/crashed distinction is available.)
func (m *VMManager) State(name string) backend.VMState {
	if !m.Exists(name) {
		return backend.VMStateUnknown
	}
	if m.IsRunning(name) {
		return backend.VMStateRunning
	}
	return backend.VMStateStopped
}

// GetIP returns the guest's static IP address. abox assigns every guest a static
// address at create (config.IPAddress, baked into cloud-init), so there is no need
// to query the guest via vmrun/open-vm-tools — the configured address is
// authoritative (and the host-only vmnet runs no DHCP).
func (m *VMManager) GetIP(name string) (string, error) {
	inst, _, err := config.Load(name)
	if err != nil {
		return "", err
	}
	return inst.IPAddress, nil
}

// GetUUID reads uuid.bios from the instance's .vmx, or "" if absent/unreadable.
func (m *VMManager) GetUUID(name string) string {
	vmx, err := vmxPathFor(name)
	if err != nil {
		return ""
	}
	return readVMXKey(vmx, "uuid.bios")
}

// readVMXKey returns the value of a key="value" line in a .vmx file, or "" if the
// key is absent or the file cannot be read. The .vmx format is one key = "value"
// per line; matching is case-insensitive on the key and tolerant of surrounding
// whitespace.
func readVMXKey(vmxPath, key string) string {
	f, err := os.Open(vmxPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	lowerKey := strings.ToLower(key)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		rawKey, rawVal, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(rawKey))
		if k != lowerKey {
			continue
		}
		return strings.Trim(strings.TrimSpace(rawVal), `"`)
	}
	return ""
}
