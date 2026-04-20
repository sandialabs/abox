//go:build darwin

package darwin

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/vfkit"
)

// VMManager implements backend.VMManager for macOS via vfkit.
type VMManager struct{}

// loadInstanceState loads the instance config and paths by name.
// Most VMManager methods receive only the instance name, so this helper
// provides access to the full config and derived paths.
func loadInstanceState(name string) (*config.Instance, *config.Paths, error) {
	inst, paths, err := config.Load(name)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load instance %q: %w", name, err)
	}
	return inst, paths, nil
}

// vfkitPIDFile returns the path to the vfkit PID file for the given instance.
func vfkitPIDFile(name string) string {
	runtimeDir := config.RuntimeDirOr(os.TempDir())
	return filepath.Join(runtimeDir, fmt.Sprintf("abox-%s-vfkit.pid", name))
}

// backendUUID extracts the VM UUID from the instance's BackendConfig.
func backendUUID(inst *config.Instance) string {
	if inst.BackendConfig == nil {
		return ""
	}
	v, ok := inst.BackendConfig["uuid"]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// backendRESTPort extracts the vfkit REST API port from BackendConfig.
func backendRESTPort(inst *config.Instance) int {
	if inst.BackendConfig == nil {
		return 0
	}
	v, ok := inst.BackendConfig["rest_port"]
	if !ok {
		return 0
	}
	switch p := v.(type) {
	case int:
		return p
	case float64:
		return int(p)
	default:
		return 0
	}
}

// restfulURI builds the vfkit REST API URI from the instance's BackendConfig.
func restfulURI(inst *config.Instance) string {
	port := backendRESTPort(inst)
	if port == 0 {
		return ""
	}
	return fmt.Sprintf("tcp://localhost:%d", port)
}

// buildVMConfig constructs a vfkit.VMConfig from an instance config and paths.
func buildVMConfig(inst *config.Instance, paths *config.Paths) vfkit.VMConfig {
	cfg := vfkit.VMConfig{
		Name:       inst.Name,
		CPUs:       inst.CPUs,
		MemoryMB:   inst.Memory,
		DiskPath:   paths.Disk,
		MACAddress: inst.MACAddress,
		ConsoleLog: filepath.Join(paths.LogsDir, "console.log"),
		RESTfulURI: restfulURI(inst),
		PIDFile:    vfkitPIDFile(inst.Name),
		LogFile:    filepath.Join(paths.LogsDir, "vfkit.log"),
	}

	// Only attach cloud-init ISO if it exists on disk.
	if _, err := os.Stat(paths.CloudInitISO); err == nil {
		cfg.CloudInitISO = paths.CloudInitISO
	}

	return cfg
}

// generateUUID creates a random UUID v4 using crypto/rand.
func generateUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate UUID: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// normalizeMAC converts a MAC address to the format used by macOS arp output.
// macOS arp strips leading zeros from each octet: "02:ab:00:0a" → "2:ab:0:a".
func normalizeMAC(mac string) string {
	parts := strings.Split(strings.ToLower(mac), ":")
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return strings.ToLower(mac)
		}
		parts[i] = strconv.FormatUint(v, 16)
	}
	return strings.Join(parts, ":")
}

// getIPByMAC parses the macOS ARP table to find an IP address for the given MAC.
// macOS arp -an output format: ? (192.168.64.3) at 2:ab:0:xx:xx:xx on bridge100 ifscope [ethernet]
func getIPByMAC(mac string) (string, error) {
	out, err := exec.Command("arp", "-an").Output()
	if err != nil {
		return "", fmt.Errorf("run arp: %w", err)
	}
	return parseARPOutput(string(out), mac)
}

// parseARPOutput extracts an IP from arp -an output matching the given MAC.
// Exported-style name but unexported for testability without exec.
func parseARPOutput(output, mac string) (string, error) {
	normalized := normalizeMAC(mac)
	for line := range strings.SplitSeq(output, "\n") {
		// Format: ? (IP) at MAC on IFACE ...
		if !strings.Contains(line, " at ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		arpMAC := strings.ToLower(fields[3])
		if arpMAC == normalized {
			// IP is in parentheses: "(192.168.64.3)"
			ip := strings.Trim(fields[1], "()")
			return ip, nil
		}
	}
	return "", errors.New("no IP address found for MAC " + mac)
}

// Create defines a new VM configuration by storing backend-specific state
// (UUID, REST port) in the instance's BackendConfig. No vfkit process is launched.
func (m *VMManager) Create(ctx context.Context, inst *config.Instance, paths *config.Paths, opts backend.VMCreateOptions) error {
	uuid := opts.UUID
	if uuid == "" {
		var err error
		uuid, err = generateUUID()
		if err != nil {
			return fmt.Errorf("failed to generate VM UUID: %w", err)
		}
	}

	port, err := vfkit.AllocateRESTPort()
	if err != nil {
		return fmt.Errorf("failed to allocate REST port: %w", err)
	}

	if inst.BackendConfig == nil {
		inst.BackendConfig = make(map[string]any)
	}
	inst.BackendConfig["uuid"] = uuid
	inst.BackendConfig["rest_port"] = port

	if err := config.Save(inst, paths); err != nil {
		return fmt.Errorf("failed to save instance config: %w", err)
	}

	logging.Debug("VM defined",
		"name", inst.Name,
		"uuid", uuid,
		"rest_port", port,
	)

	return nil
}

// Start launches the vfkit process for the instance.
func (m *VMManager) Start(ctx context.Context, name string) error {
	inst, paths, err := loadInstanceState(name)
	if err != nil {
		return err
	}

	pidFile := vfkitPIDFile(name)

	if vfkit.IsRunning(pidFile) {
		return fmt.Errorf("VM %q is already running", name)
	}

	// Clean up stale PID file from a previous crash.
	_ = vfkit.CleanupPIDFile(pidFile)

	cfg := buildVMConfig(inst, paths)

	// TODO(phase-11.3): replace nil with the caller-side socketpair end
	// that is connected to a vmnet-helper process. Currently fails fast
	// with "vfkit: netFD is required" — expected until 11.3 lands.
	pid, err := vfkit.StartVM(cfg, nil)
	if err != nil {
		return fmt.Errorf("failed to start VM: %w", err)
	}

	logging.Debug("VM started", "name", name, "pid", pid)
	return nil
}

// Stop gracefully stops a running VM via the vfkit REST API,
// falling back to SIGTERM+SIGKILL if the API is unreachable.
// The caller (stop command) polls IsRunning() until the process exits,
// so we always fall through to StopVM which handles PID file cleanup.
func (m *VMManager) Stop(ctx context.Context, name string) error {
	pidFile := vfkitPIDFile(name)

	inst, _, err := loadInstanceState(name)
	if err != nil {
		return vfkit.StopVM(pidFile)
	}

	// Try REST API graceful stop first (ACPI shutdown).
	if uri := restfulURI(inst); uri != "" {
		if err := vfkit.RequestStop(uri); err != nil {
			logging.Debug("REST API stop failed, falling back to signal", "error", err)
		} else {
			// REST API accepted the stop request. Fall through to StopVM
			// which will wait for the process to exit and clean up the PID file.
			logging.Debug("REST API stop requested, waiting for process exit")
		}
	}

	return vfkit.StopVM(pidFile)
}

// ForceStop forcefully stops a running VM via SIGKILL.
func (m *VMManager) ForceStop(ctx context.Context, name string) error {
	return vfkit.ForceStopVM(vfkitPIDFile(name))
}

// Remove ensures the VM is stopped and clears backend state.
func (m *VMManager) Remove(ctx context.Context, name string) error {
	pidFile := vfkitPIDFile(name)

	if vfkit.IsRunning(pidFile) {
		if err := m.ForceStop(ctx, name); err != nil {
			return fmt.Errorf("failed to stop VM before removal: %w", err)
		}
	}

	// Clean up stale PID file.
	_ = vfkit.CleanupPIDFile(pidFile)

	// Clear backend state so Exists returns false.
	inst, paths, err := loadInstanceState(name)
	if err != nil {
		// Remove is idempotent: a missing/unreadable config means there's
		// nothing left to clear, and we don't want to fail a caller that's
		// just cleaning up a half-created instance.
		logging.Debug("skipping backend state cleanup: config unreadable", "name", name, "error", err)
		return nil
	}

	delete(inst.BackendConfig, "uuid")
	delete(inst.BackendConfig, "rest_port")

	if err := config.Save(inst, paths); err != nil {
		return fmt.Errorf("failed to save config after removal: %w", err)
	}

	return nil
}

// Exists checks if a VM has been defined (Create was called).
func (m *VMManager) Exists(name string) bool {
	inst, _, err := loadInstanceState(name)
	if err != nil {
		return false
	}
	return backendUUID(inst) != ""
}

// IsRunning checks if the vfkit process is alive.
func (m *VMManager) IsRunning(name string) bool {
	return vfkit.IsRunning(vfkitPIDFile(name))
}

// State returns the current VM state.
func (m *VMManager) State(name string) backend.VMState {
	pidFile := vfkitPIDFile(name)

	if !vfkit.IsRunning(pidFile) {
		// Check if there's a stale PID file (indicates crash).
		if _, err := os.Stat(pidFile); err == nil {
			return backend.VMStateCrashed
		}
		return backend.VMStateStopped
	}

	// Process is alive — try the REST API for detailed state.
	inst, _, err := loadInstanceState(name)
	if err != nil {
		return backend.VMStateRunning // process alive, assume running
	}

	uri := restfulURI(inst)
	if uri == "" {
		return backend.VMStateRunning
	}

	state, err := vfkit.VMState(uri)
	if err != nil {
		return backend.VMStateRunning // process alive, API not ready
	}

	switch state {
	case "VirtualMachineStateRunning":
		return backend.VMStateRunning
	case "VirtualMachineStateStopped":
		return backend.VMStateStopped
	case "VirtualMachineStatePaused":
		return backend.VMStatePaused
	default:
		return backend.VMStateUnknown
	}
}

// GetIP returns the IP address of a running VM by looking up its MAC in the ARP table.
func (m *VMManager) GetIP(name string) (string, error) {
	inst, _, err := loadInstanceState(name)
	if err != nil {
		return "", err
	}

	if inst.MACAddress == "" {
		return "", errors.New("no MAC address configured for instance")
	}

	return getIPByMAC(inst.MACAddress)
}

// GetUUID returns the UUID of a defined VM.
func (m *VMManager) GetUUID(name string) string {
	inst, _, err := loadInstanceState(name)
	if err != nil {
		return ""
	}
	return backendUUID(inst)
}

// Redefine updates an existing VM definition, preserving the UUID.
func (m *VMManager) Redefine(ctx context.Context, inst *config.Instance, paths *config.Paths, opts backend.VMCreateOptions) error {
	if opts.UUID == "" {
		opts.UUID = m.GetUUID(inst.Name)
	}
	return m.Create(ctx, inst, paths, opts)
}
