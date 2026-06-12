//go:build darwin

package vfkit

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/vfkit"
	"github.com/sandialabs/abox/internal/vmnethelper"
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

// vmnetHelperPIDFile returns the path to the vmnet-helper PID file for the
// given instance. Each VM has its own helper process (= its own bridgeN).
func vmnetHelperPIDFile(name string) string {
	runtimeDir := config.RuntimeDirOr(os.TempDir())
	return filepath.Join(runtimeDir, fmt.Sprintf("abox-%s-vmnethelper.pid", name))
}

// deriveVMNetAddresses computes the vmnet-helper --subnet-mask and
// --end-address for the instance's allocated subnet. The DHCP pool's start
// address is the gateway itself (the caller passes inst.Gateway to
// vmnet-helper directly); the end address is the last usable host of the
// subnet (broadcast − 1). The mask and end are derived from the actual CIDR,
// so this works for any IPv4 prefix, not just /24.
//
// It rejects anything that couldn't host the VM: a non-IPv4 CIDR, a subnet
// smaller than /30 (no room for both a gateway and a DHCP client), or a
// gateway that isn't a usable host strictly below the pool's end address.
func deriveVMNetAddresses(subnetCIDR, gateway string) (subnetMask, endAddress string, err error) {
	_, ipNet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return "", "", fmt.Errorf("parse subnet %q: %w", subnetCIDR, err)
	}
	network := ipNet.IP.To4()
	mask := net.IP(ipNet.Mask).To4()
	if network == nil || mask == nil {
		return "", "", fmt.Errorf("subnet %q is not IPv4", subnetCIDR)
	}

	gw := net.ParseIP(gateway).To4()
	if gw == nil {
		return "", "", fmt.Errorf("invalid IPv4 gateway %q", gateway)
	}

	netNum := binary.BigEndian.Uint32(network)
	hostMask := ^binary.BigEndian.Uint32(mask) // 1s across the host bits
	// hostMask is (number of addresses − 1). A /30 has hostMask 3 (network +
	// gateway + one DHCP host + broadcast); anything smaller can't host a VM.
	if hostMask < 3 {
		return "", "", fmt.Errorf("subnet %s is too small (need at least a /30)", subnetCIDR)
	}
	broadcastNum := netNum | hostMask
	endNum := broadcastNum - 1 // last usable host; broadcast is reserved

	gwNum := binary.BigEndian.Uint32(gw)
	// Gateway must be a host above the network address and strictly below the
	// pool end, leaving at least one address for the VM's DHCP lease.
	if gwNum <= netNum || gwNum >= endNum {
		return "", "", fmt.Errorf(
			"gateway %s is not a usable host below the end of subnet %s", gateway, subnetCIDR)
	}

	subnetMask = fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
	endIP := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(endIP, endNum)
	endAddress = endIP.String()
	return subnetMask, endAddress, nil
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

// Start launches the vmnet-helper and vfkit processes for the instance,
// connected by a datagram socketpair carrying raw L2 frames.
//
// The flow:
//  1. Resolve the vmnet-helper binary and derive the per-VM addressing from
//     the instance's allocated subnet.
//  2. Create an AF_UNIX SOCK_DGRAM socketpair — vmnet-helper requires
//     datagram framing (one raw ethernet frame per datagram).
//  3. Launch vmnet-helper in host mode pinned to the instance's subnet; it
//     consumes one socketpair end.
//  4. Reconcile: the gateway vmnet hands out must equal the one already baked
//     into cloud-init, else the subnet is contended — fail loudly.
//  5. Launch vfkit with virtio-net on the other socketpair end.
//  6. Persist the resolved bridge so post-boot pf rules can scope to it.
func (m *VMManager) Start(_ context.Context, name string) error {
	inst, paths, err := loadInstanceState(name)
	if err != nil {
		return err
	}

	pidFile := vfkitPIDFile(name)
	helperPID := vmnetHelperPIDFile(name)

	if vfkit.IsRunning(pidFile) {
		return fmt.Errorf("VM %q is already running", name)
	}

	// Clean up stale PID files from a previous crash.
	_ = vfkit.CleanupPIDFile(pidFile)
	_ = vmnethelper.CleanupPIDFile(helperPID)

	binPath, err := vmnethelper.ResolveBinaryPath()
	if err != nil {
		return fmt.Errorf("failed to locate vmnet-helper: %w", err)
	}

	subnetMask, endAddress, err := deriveVMNetAddresses(inst.Subnet, inst.Gateway)
	if err != nil {
		return err
	}

	// Datagram socketpair: vmnetEnd → vmnet-helper, vfkitEnd → vfkit virtio-net.
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("create socketpair: %w", err)
	}
	vmnetEnd := os.NewFile(uintptr(fds[0]), "vmnet")
	vfkitEnd := os.NewFile(uintptr(fds[1]), "vfkit")

	// Defensive cleanup: vmnethelper.Start and vfkit.StartVM each close their
	// own end once launched, but not on every early-return path. *os.File.Close
	// is idempotent, so closing an already-consumed end is a harmless no-op.
	// Once both have launched (launched=true) we leave the fds to the children.
	launched := false
	defer func() {
		if !launched {
			_ = vmnetEnd.Close()
			_ = vfkitEnd.Close()
		}
	}()

	helperCfg := vmnethelper.HelperConfig{
		Name:          name,
		InterfaceID:   backendUUID(inst),
		OperationMode: vmnethelper.ModeHost,
		SocketFD:      vmnethelper.ChildSocketFD, // ExtraFiles[0] → fd 3 in the child
		UseSudo:       vmnethelper.NeedsSudo(),
		BinaryPath:    binPath,
		PIDFile:       helperPID,
		LogFile:       filepath.Join(paths.LogsDir, "vmnet-helper.log"),
		StartAddress:  inst.Gateway,
		EndAddress:    endAddress,
		SubnetMask:    subnetMask,
	}

	res, err := vmnethelper.Start(helperCfg, vmnetEnd)
	if err != nil {
		return fmt.Errorf("failed to start vmnet-helper: %w", err)
	}

	// Determinism guard (option A): cloud-init baked in inst.Gateway pre-boot.
	// If vmnet handed out a different subnet, someone else holds ours and the
	// VM's networking would be misconfigured — fail rather than boot broken.
	if res.StartAddress != inst.Gateway {
		_ = vmnethelper.ForceStop(helperPID)
		return fmt.Errorf(
			"vmnet-helper assigned gateway %s but instance %q expects %s "+
				"(subnet %s may be in use by another process)",
			res.StartAddress, name, inst.Gateway, inst.Subnet)
	}

	cfg := buildVMConfig(inst, paths)
	cfg.NetFD = vfkit.NetFDChild

	pid, err := vfkit.StartVM(cfg, vfkitEnd)
	if err != nil {
		// Avoid an orphaned helper + bridge.
		_ = vmnethelper.ForceStop(helperPID)
		return fmt.Errorf("failed to start VM: %w", err)
	}
	launched = true

	// Persist the resolved bridge so the post-boot pf step can scope the
	// per-VM IPv6 block to this interface.
	if inst.BackendConfig == nil {
		inst.BackendConfig = make(map[string]any)
	}
	inst.BackendConfig["bridge"] = res.BridgeInterface
	if err := config.Save(inst, paths); err != nil {
		logging.Warn("failed to persist bridge interface", "instance", name, "error", err)
	}

	logging.Debug("VM started",
		"name", name,
		"pid", pid,
		"helper_pid", res.PID,
		"bridge", res.BridgeInterface,
		"gateway", res.StartAddress,
	)
	return nil
}

// Stop gracefully stops a running VM via the vfkit REST API,
// falling back to SIGTERM+SIGKILL if the API is unreachable.
// The caller (stop command) polls IsRunning() until the process exits,
// so we always fall through to StopVM which handles PID file cleanup.
func (m *VMManager) Stop(_ context.Context, name string) error {
	pidFile := vfkitPIDFile(name)
	helperPID := vmnetHelperPIDFile(name)

	// Try REST API graceful stop first (ACPI shutdown).
	if inst, _, err := loadInstanceState(name); err == nil {
		if uri := restfulURI(inst); uri != "" {
			if rerr := vfkit.RequestStop(uri); rerr != nil {
				logging.Debug("REST API stop failed, falling back to signal", "error", rerr)
			} else {
				logging.Debug("REST API stop requested, waiting for process exit")
			}
		}
	}

	// Stop vfkit before the helper so the VM releases the socket first.
	vmErr := vfkit.StopVM(pidFile)

	// vmnet-helper does NOT auto-exit when vfkit closes the socket, so this
	// teardown is mandatory — otherwise every stop leaks a helper + bridge.
	if herr := vmnethelper.Stop(helperPID); herr != nil {
		logging.Debug("failed to stop vmnet-helper", "instance", name, "error", herr)
	}

	return vmErr
}

// ForceStop forcefully stops the VM and its vmnet-helper via SIGKILL.
func (m *VMManager) ForceStop(_ context.Context, name string) error {
	vmErr := vfkit.ForceStopVM(vfkitPIDFile(name))
	if herr := vmnethelper.ForceStop(vmnetHelperPIDFile(name)); herr != nil {
		logging.Debug("failed to force-stop vmnet-helper", "instance", name, "error", herr)
	}
	return vmErr
}

// Remove ensures the VM is stopped and clears backend state.
func (m *VMManager) Remove(_ context.Context, name string) error {
	pidFile := vfkitPIDFile(name)
	helperPID := vmnetHelperPIDFile(name)

	// Best-effort force-stop of both processes; tolerate either being absent.
	if vfkit.IsRunning(pidFile) {
		_ = vfkit.ForceStopVM(pidFile)
	}
	if vmnethelper.IsRunning(helperPID) {
		_ = vmnethelper.ForceStop(helperPID)
	}

	// Clean up stale PID files.
	_ = vfkit.CleanupPIDFile(pidFile)
	_ = vmnethelper.CleanupPIDFile(helperPID)

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
	delete(inst.BackendConfig, "bridge")

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
