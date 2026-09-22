//go:build darwin

package vfkit

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/vfkit"
	"github.com/sandialabs/abox/internal/vmnethelper"
)

// VMManager implements backend.VMManager for macOS via vfkit.
type VMManager struct{}

// Seams for testing Start's fail-closed teardown in isolation: these calls
// spawn real processes (vfkit, root vmnet-helper) or touch on-disk config, so
// tests swap them for fakes to exercise the security-critical branches — the
// VerifyLive fail-closed teardown (finding F13) and the bridge-persist
// fail-closed teardown (finding F11) — without any real processes or files.
// Start is the only caller that routes through these vars; the rest of the file
// calls the concrete functions directly. Matches the var-seam pattern in
// pkg/cmd/start/start.go.
var (
	startVMFn         = vfkit.StartVM
	verifyLiveFn      = vfkit.VerifyLive
	forceStopVMFn     = vfkit.ForceStopVM
	helperStartFn     = vmnethelper.Start
	helperForceStopFn = vmnethelper.ForceStop
	saveConfigFn      = config.Save
)

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

// pidFileName builds the per-instance PID file basename for a given component.
func pidFileName(name, component string) string {
	return fmt.Sprintf("abox-%s-%s.pid", name, component)
}

// legacyPIDDir is where PID files used to live: the per-user runtime dir, which
// on macOS resolves to $TMPDIR and is purged by the OS after ~3 idle days
// (finding F12). PID files now live under the instance directory (see
// instanceRunDir), but we still read-fall-back here so a VM that was started
// under the old layout stays manageable across the upgrade.
func legacyPIDDir() string {
	return config.RuntimeDirOr(os.TempDir())
}

// instanceRunDir returns the per-instance directory that holds PID files. It
// lives under the instance's on-disk data directory (paths.Instance/run) so it
// survives macOS's periodic purge of $TMPDIR, unlike legacyPIDDir. The dir is
// created if missing. On any failure resolving the instance path it falls back
// to the legacy runtime dir so liveness tracking never silently breaks.
func instanceRunDir(name string) string {
	paths, err := config.GetPaths(name)
	if err != nil {
		return legacyPIDDir()
	}
	runDir := filepath.Join(paths.Instance, "run")
	if mkErr := os.MkdirAll(runDir, 0o700); mkErr != nil {
		logging.Debug("failed to create instance run dir, falling back to runtime dir",
			"instance", name, "dir", runDir, "error", mkErr)
		return legacyPIDDir()
	}
	return runDir
}

// resolvePIDFile returns the active PID file path for a component, preferring
// the persistent per-instance run dir. If no file exists there but a legacy
// $TMPDIR file does, it returns the legacy path so an already-running VM stays
// manageable. New writers always use the per-instance path.
func resolvePIDFile(name, component string) string {
	base := pidFileName(name, component)
	primary := filepath.Join(instanceRunDir(name), base)
	if _, err := os.Stat(primary); err == nil {
		return primary
	}
	legacy := filepath.Join(legacyPIDDir(), base)
	if primary != legacy {
		if _, err := os.Stat(legacy); err == nil {
			return legacy
		}
	}
	return primary
}

// vfkitPIDFile returns the path to the vfkit PID file for the given instance.
func vfkitPIDFile(name string) string {
	return resolvePIDFile(name, "vfkit")
}

// vmnetHelperPIDFile returns the path to the vmnet-helper PID file for the
// given instance. Each VM has its own helper process (= its own bridgeN).
func vmnetHelperPIDFile(name string) string {
	return resolvePIDFile(name, "vmnethelper")
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
	s, _ := inst.BackendString(config.BackendKeyUUID)
	return s
}

// backendRESTPort extracts the vfkit REST API port from BackendConfig.
func backendRESTPort(inst *config.Instance) int {
	p, _ := inst.BackendInt(config.BackendKeyRESTPort)
	return p
}

// restfulURI builds the vfkit REST API URI from the instance's BackendConfig.
// It uses the 127.0.0.1 literal (not "localhost") to match AllocateRESTPort,
// which reserves the port on 127.0.0.1: on a dual-stack Mac "localhost" can
// resolve to ::1 first, so binding/querying "localhost" could miss the reserved
// v4 port and make RequestStop fail — which would silently degrade every graceful
// stop to a SIGTERM/SIGKILL force-kill.
func restfulURI(inst *config.Instance) string {
	port := backendRESTPort(inst)
	if port == 0 {
		return ""
	}
	return fmt.Sprintf("tcp://127.0.0.1:%d", port)
}

// buildVMConfig constructs a vfkit.VMConfig from an instance config and paths.
func buildVMConfig(inst *config.Instance, paths *config.Paths) vfkit.VMConfig {
	cfg := vfkit.VMConfig{
		Name:          inst.Name,
		CPUs:          inst.CPUs,
		MemoryMB:      inst.Memory,
		DiskPath:      instanceDiskPath(paths),
		MACAddress:    inst.MACAddress,
		ConsoleLog:    filepath.Join(paths.LogsDir, "console.log"),
		RESTfulURI:    restfulURI(inst),
		PIDFile:       vfkitPIDFile(inst.Name),
		LogFile:       filepath.Join(paths.LogsDir, "vfkit.log"),
		NetSocketPath: paths.VMNetSocket,
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
	inst.BackendConfig[config.BackendKeyUUID] = uuid
	inst.BackendConfig[config.BackendKeyRESTPort] = port

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
// connected by a unix datagram socket the helper binds and vfkit connects to.
//
// The flow:
//  1. Resolve the vmnet-helper binary and derive the per-VM addressing from
//     the instance's allocated subnet.
//  2. Launch vmnet-helper in host mode pinned to the instance's subnet, told to
//     bind its datagram socket at paths.VMNetSocket (--socket). No fd is passed,
//     so nothing has to survive sudo's closefrom.
//  3. Reconcile: the gateway vmnet hands out must equal the one already baked
//     into cloud-init, else the subnet is contended — fail loudly.
//  4. Wait for the socket to be bound, then launch vfkit with its virtio-net
//     device pointed at that socket path (unixSocketPath); vfkit connects.
//  5. Persist the resolved bridge so post-boot pf rules can scope to it.
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

	if err := reclaimOrphanedHelper(name, helperPID); err != nil {
		return err
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

	// vmnet-helper and vfkit are connected over a unix datagram socket the helper
	// binds (--socket) and vfkit connects to (unixSocketPath). Using a bound
	// socket instead of an inherited fd keeps anything from having to cross the
	// sudo boundary (sudo's closefrom would strip an inherited fd). Ensure the
	// run dir exists, validate the path length (macOS sun_path cap), and clear a
	// stale socket from a prior crash so the helper's bind won't EADDRINUSE — this
	// single pre-launch removal is why no teardown-time removal is needed (bind
	// only fails on a pre-existing file).
	sockPath := paths.VMNetSocket
	if err := config.ValidateSocketPaths(paths); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(sockPath), 0o700); err != nil {
		return fmt.Errorf("failed to create vmnet socket dir: %w", err)
	}
	_ = os.Remove(sockPath)

	helperCfg := vmnethelper.HelperConfig{
		Name:          name,
		InterfaceID:   backendUUID(inst),
		OperationMode: vmnethelper.ModeHost,
		SocketPath:    sockPath,
		UseSudo:       vmnethelper.NeedsSudo(),
		BinaryPath:    binPath,
		PIDFile:       helperPID,
		LogFile:       filepath.Join(paths.LogsDir, "vmnet-helper.log"),
		StartAddress:  inst.Gateway,
		EndAddress:    endAddress,
		SubnetMask:    subnetMask,
	}

	res, err := helperStartFn(helperCfg)
	if err != nil {
		return fmt.Errorf("failed to start vmnet-helper: %w", err)
	}

	// Determinism guard (option A): cloud-init baked in inst.Gateway pre-boot.
	// If vmnet handed out a different subnet, someone else holds ours and the
	// VM's networking would be misconfigured — fail rather than boot broken.
	if res.StartAddress != inst.Gateway {
		_ = helperForceStopFn(helperPID)
		return fmt.Errorf(
			"vmnet-helper assigned gateway %s but instance %q expects %s "+
				"(subnet %s may be in use by another process)",
			res.StartAddress, name, inst.Gateway, inst.Subnet)
	}

	// Allocate a fresh REST port at every Start rather than reusing the one
	// persisted at Create (finding F14). The Create-time port is bound and
	// released immediately, so anything could have claimed it in the interim;
	// reusing it risks vfkit dying right after a "successful" start. Allocate
	// now, persist it (other code reads rest_port from BackendConfig to talk to
	// the VM), and feed it into the launch config.
	port, err := vfkit.AllocateRESTPort()
	if err != nil {
		_ = helperForceStopFn(helperPID)
		return fmt.Errorf("failed to allocate REST port: %w", err)
	}
	if inst.BackendConfig == nil {
		inst.BackendConfig = make(map[string]any)
	}
	inst.BackendConfig[config.BackendKeyRESTPort] = port

	// vmnet-helper emits its start JSON after bringing up the vmnet interface,
	// but does not guarantee the --socket path is bound yet. vfkit connects once
	// and dies if the socket is absent (no retry), so wait for it to appear.
	if err := waitForSocket(sockPath, socketBindTimeout); err != nil {
		_ = helperForceStopFn(helperPID)
		return fmt.Errorf("vmnet-helper socket %s did not appear: %w", sockPath, err)
	}

	cfg := buildVMConfig(inst, paths)

	pid, err := startVMFn(cfg)
	if err != nil {
		// Avoid an orphaned helper + bridge.
		_ = helperForceStopFn(helperPID)
		return fmt.Errorf("failed to start VM: %w", err)
	}

	// vfkit was launched detached; exec.Start() succeeding only means the fork
	// happened, not that vfkit is healthy (finding F13). An instant death — a
	// taken REST port, corrupt disk, EFI store error — would otherwise sail
	// through as a "successful" start, leaving a helper + bridge up for a dead
	// VM. Verify liveness within a short grace window before declaring success;
	// on failure, tear everything down and surface the vfkit.log tail.
	if err := verifyLiveFn(cfg.PIDFile, cfg.RESTfulURI, vmStartGraceWindow); err != nil {
		_ = forceStopVMFn(cfg.PIDFile)
		_ = helperForceStopFn(helperPID)
		tail := vfkit.LogTail(cfg.LogFile, vfkitLogTailLines)
		if tail != "" {
			return fmt.Errorf("VM %q died immediately after launch: %w\nvfkit.log:\n%s", name, err, tail)
		}
		return fmt.Errorf("VM %q died immediately after launch: %w", name, err)
	}

	// Persist the resolved bridge (for post-boot pf scoping) and the fresh REST
	// port. This must succeed: without the bridge, setupPostBootFirewall hard-
	// fails with the VM already up and the entire per-instance pf ruleset (DNS
	// redirect, default-deny, IPv6 block) never applied, leaving a running VM
	// with zero egress filtering and no self-heal on retry (finding F11). Treat
	// it as fatal and tear down vfkit + helper, mirroring the StartVM error path.
	inst.BackendConfig[config.BackendKeyBridge] = res.BridgeInterface
	if err := saveConfigFn(inst, paths); err != nil {
		_ = forceStopVMFn(cfg.PIDFile)
		_ = helperForceStopFn(helperPID)
		return fmt.Errorf("failed to persist bridge interface for instance %q (VM torn down to keep the sandbox closed): %w", name, err)
	}

	logging.Debug("VM started",
		"name", name,
		"pid", pid,
		"helper_pid", res.PID,
		"bridge", res.BridgeInterface,
		"gateway", res.StartAddress,
		"rest_port", port,
	)
	return nil
}

// reclaimOrphanedHelper stops a vmnet-helper left over from a previous crash.
// vmnet-helper does not auto-exit when vfkit dies, so an orphan can survive
// holding our pinned subnet/interface-id. Launching a second helper on top of
// it hangs (it never emits its start JSON), so reclaim the orphan first: stop
// it gracefully, force-kill on failure. Returns an error if the orphan survives
// both, so Start can abort with an actionable message rather than launching a new
// helper on top of it (which hangs, then fails with an opaque read-timeout).
func reclaimOrphanedHelper(name, helperPID string) error {
	if !vmnethelper.IsRunning(helperPID) {
		return nil
	}
	logging.Warn("found orphaned vmnet-helper from a previous crash, stopping it",
		"instance", name)
	// Audit the reclaim: an orphaned root-owned helper survived a crash holding a
	// vmnet interface, and abox is tearing it down. The stop/force-stop calls below
	// emit their own outcome audits (vmnet-helper.stop / .force-stop).
	logging.Audit("vmnet-helper.reclaim-orphan", "instance", name)
	if herr := vmnethelper.Stop(helperPID); herr != nil {
		logging.Warn("graceful stop of orphaned vmnet-helper failed, force-killing",
			"instance", name, "error", herr)
		if ferr := vmnethelper.ForceStop(helperPID); ferr != nil {
			logging.Warn("failed to force-stop orphaned vmnet-helper",
				"instance", name, "error", ferr)
		}
	}
	if vmnethelper.IsRunning(helperPID) {
		return fmt.Errorf("an orphaned vmnet-helper (from a previous crash) is still running and holds this instance's network; run `abox stop %s` from a terminal to stop it (elevated), then retry", name)
	}
	return nil
}

// socketBindTimeout bounds how long Start waits for vmnet-helper to bind its
// --socket path (after emitting its start JSON) before launching vfkit, which
// connects once and would die if the socket isn't there yet. Matched to the
// helper's own start-JSON read timeout so a slow host isn't cut off early.
const socketBindTimeout = 5 * time.Second

// waitForSocket polls until path exists or timeout elapses. It only checks for
// the socket file's presence: a bound unix datagram socket is connectable as
// soon as its inode exists (no listen backlog), so existence is a sufficient
// readiness signal for vfkit to connect.
func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %v", timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// vmStartGraceWindow bounds how long Start waits, after launching vfkit, to
// confirm the process is alive and its REST API answers before declaring the
// start a success. A short window is enough to catch instant deaths (taken REST
// port, corrupt disk, EFI store error) without slowing the common path.
const vmStartGraceWindow = 2 * time.Second

// vfkitLogTailLines is how many trailing vfkit.log lines to surface when a
// launch dies, enough to show the fatal error without dumping the whole boot.
const vfkitLogTailLines = 20

// gracefulStopWindow bounds how long Stop waits for vfkit to exit on its own
// after a REST/ACPI shutdown request before falling back to signals. It sits
// just under the stop command's 60s grace poll so that, in the common case,
// the guest gets a real chance to flush and exit cleanly rather than being
// force-killed after vfkit's own ~5s SIGTERM handler.
const gracefulStopWindow = 55 * time.Second

// Stop gracefully stops a running VM. It requests an ACPI shutdown via the
// vfkit REST API and then blocks (honoring ctx for cancellation) for up to
// gracefulStopWindow for vfkit to exit on its own. If the REST request fails
// or the grace window elapses, it falls back to vfkit.StopVM (SIGTERM → 5s →
// SIGKILL). The vmnet-helper is always torn down afterwards, since it does NOT
// auto-exit when vfkit closes the socket.
//
// Stop is synchronous: when it returns, vfkit has exited and the helper has
// been stopped. The stop command's grace poll therefore sees IsRunning()==false
// almost immediately after Stop returns.
func (m *VMManager) Stop(ctx context.Context, name string) error {
	pidFile := vfkitPIDFile(name)
	helperPID := vmnetHelperPIDFile(name)

	graceful, err := requestGracefulExit(ctx, name, pidFile)
	if err != nil {
		// Context cancelled mid-wait: the ACPI request may not have completed, so
		// force vfkit down BEFORE tearing down the helper — otherwise a cancelled
		// stop can orphan a running vfkit whose network peer (vmnet-helper) has been
		// killed, blocking the next start with "VM is already running".
		_ = vfkit.ForceStopVM(pidFile)
		stopHelper(name, helperPID)
		return err
	}

	// Fall back to SIGTERM+SIGKILL when the REST path didn't get vfkit to exit.
	var vmErr error
	if !graceful {
		// Stop vfkit before the helper so the VM releases the socket first.
		vmErr = vfkit.StopVM(pidFile)
	}

	// vmnet-helper does NOT auto-exit when vfkit closes the socket, so this
	// teardown is mandatory — otherwise every stop leaks a helper + bridge.
	stopHelper(name, helperPID)

	return vmErr
}

// requestGracefulExit issues a REST/ACPI stop and waits up to
// gracefulStopWindow for vfkit to exit on its own, honoring ctx for
// cancellation. The grace window is only honored when the REST request
// actually succeeded; if the instance state can't be loaded, no REST URI is
// configured, or the request fails, there is nothing to wait for and the
// caller falls straight to signals. Returns whether vfkit exited gracefully;
// a non-nil error means ctx was cancelled mid-wait.
func requestGracefulExit(ctx context.Context, name, pidFile string) (bool, error) {
	inst, _, err := loadInstanceState(name)
	if err != nil {
		logging.Debug("could not load instance state for REST stop, falling back to signal",
			"instance", name, "error", err)
		return false, nil
	}
	uri := restfulURI(inst)
	if uri == "" {
		return false, nil
	}
	if rerr := vfkit.RequestStop(uri); rerr != nil {
		logging.Debug("REST API stop failed, falling back to signal", "error", rerr)
		return false, nil
	}

	logging.Debug("REST API stop requested, waiting for process exit")
	exited, werr := vfkit.WaitForExit(ctx, pidFile, gracefulStopWindow)
	if werr != nil {
		return false, werr
	}
	if !exited {
		logging.Warn("VM did not exit within graceful window, falling back to signal",
			"instance", name)
	}
	return exited, nil
}

// stopHelper gracefully stops the instance's vmnet-helper, logging at Warn on
// failure — a leaked root helper process is worth surfacing, not hiding behind
// a debug line.
func stopHelper(name, helperPID string) {
	if herr := vmnethelper.Stop(helperPID); herr != nil {
		logging.Warn("failed to stop vmnet-helper", "instance", name, "error", herr)
	}
}

// ForceStop forcefully stops the VM and its vmnet-helper via SIGKILL.
func (m *VMManager) ForceStop(_ context.Context, name string) error {
	vmErr := vfkit.ForceStopVM(vfkitPIDFile(name))
	if herr := vmnethelper.ForceStop(vmnetHelperPIDFile(name)); herr != nil {
		logging.Warn("failed to force-stop vmnet-helper", "instance", name, "error", herr)
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

	delete(inst.BackendConfig, config.BackendKeyUUID)
	delete(inst.BackendConfig, config.BackendKeyRESTPort)
	delete(inst.BackendConfig, config.BackendKeyBridge)

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

// GetIP returns the guest's static IP address. abox assigns every guest a static
// address at create (config.IPAddress, baked into cloud-init), so there is no DHCP
// lease or ARP entry to scrape — the configured address is authoritative
// (config-truth, not observed-truth: it is not re-validated against the running
// guest here; ssh reachability elsewhere is what confirms the guest applied it).
func (m *VMManager) GetIP(name string) (string, error) {
	inst, _, err := loadInstanceState(name)
	if err != nil {
		return "", err
	}
	return inst.IPAddress, nil
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
