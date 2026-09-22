package start

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/cloudinit"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/dnsfilter"
	"github.com/sandialabs/abox/internal/httpfilter"
	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/monitor"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/sshutil"
	"github.com/sandialabs/abox/internal/tetragon"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// Options holds the options for the start command.
type Options struct {
	Factory *factory.Factory
	Brief   bool     // Suppress final summary/next-steps output
	Names   []string // Instance names to start
}

// NewCmdStart creates a new start command.
func NewCmdStart(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "start <name...>",
		Short: "Start one or more abox instances",
		Long:  "Start one or more stopped instances. Launches DNS and HTTP filters, sets up networking, and boots the VM.",
		Example: `  abox start dev                           # Start a single instance
  abox start dev staging                   # Start multiple instances`,
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: completion.Repeat(completion.StoppedInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Names = args
			if runF != nil {
				return runF(opts)
			}
			ctx := cmd.Context()
			return cmdutil.ForEach(args, func(name string) error {
				return runStart(ctx, opts, name)
			})
		},
	}

	return cmd
}

// Run executes the start command with the given options and instance name.
func Run(ctx context.Context, opts *Options, name string) error {
	factory.Ensure(&opts.Factory)
	return runStart(ctx, opts, name)
}

func (o *Options) out() io.Writer { return o.Factory.IO.Out }

func runStart(ctx context.Context, opts *Options, name string) error {
	inst, paths, err := instance.LoadRequired(name)
	if err != nil {
		return err
	}

	// Legacy root-owned storage can't be managed unprivileged; require migration.
	if err := instance.RequireMigrated(inst, paths); err != nil {
		return err
	}

	// Get the backend for this instance
	be, err := opts.Factory.BackendFor(name)
	if err != nil {
		return fmt.Errorf("failed to get backend: %w", err)
	}

	w := opts.out()

	// Check if already running
	if be.VM().IsRunning(name) {
		fmt.Fprintf(w, "Instance %q is already running.\n", name)
		// Filter and monitor daemons can crash independently of the VM
		// (panic, OOM, kill -9). Recover any that died so the user doesn't
		// have to abox stop && abox start to get filtering back. Each
		// start* call is a no-op when its daemon is alive.
		return recoverDaemons(w, be, name, inst, paths, opts.Brief)
	}

	if err := ensureNetwork(ctx, w, be, inst); err != nil {
		return err
	}

	if err := startFilters(ctx, w, opts.Factory, be, name, inst, paths); err != nil {
		return err
	}

	if err := startVMAndApplyFilter(ctx, w, be, name, inst, paths); err != nil {
		return err
	}

	ip, ready := waitForReady(w, inst, paths)

	if !opts.Brief {
		ipInfo := " at " + ip
		if !ready {
			ipInfo += " (not yet reachable)"
		}
		fmt.Fprintf(w, "\nInstance %q started%s\n", name, ipInfo)
		fmt.Fprintf(w, "\nSSH: abox ssh %s\n", name)
	}

	logging.AuditInstance(name, logging.ActionInstanceStart,
		"ip", ip,
	)

	return nil
}

// ensureNetwork ensures the instance's network exists and is active.
//
// The exists-check-then-create span holds config.AcquireLock, mirroring create and
// remove. Network().Create can perform a cross-process read-modify-write of shared
// state (the VMware backend edits the root-owned /etc/vmware/networking answer-file
// and the vmnet allocation registry); its documented contract is that the caller
// holds this lock. create/remove already do, but start reaches Create too (a
// registry entry can exist while the vmnet itself was removed out-of-band), so
// without the lock two concurrent starts — or a start racing create/remove — could
// interleave and clobber a peer instance's network config.
func ensureNetwork(ctx context.Context, w io.Writer, be backend.Backend, inst *config.Instance) error {
	if err := config.AcquireLock(); err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = config.ReleaseLock() }()

	if !be.Network().Exists(inst.Bridge) {
		fmt.Fprintln(w, "Creating network...")
		if err := be.Network().Create(ctx, inst); err != nil {
			return fmt.Errorf("failed to create network: %w", err)
		}
	}
	if !be.Network().IsActive(inst.Bridge) {
		fmt.Fprintln(w, "Starting network...")
		if err := be.Network().Start(ctx, inst.Bridge); err != nil {
			return fmt.Errorf("failed to start network: %w", err)
		}
	}
	return nil
}

// Seams for testing recoverDaemons in isolation: the daemon starts spawn real
// child processes and applyFilteredFn (instance.ApplyFiltered) touches the host
// firewall, so tests swap these to no-ops/fakes to exercise the egress re-assert
// nil-gate and error-wrapping. Matches the var-seam pattern in
// filter_orphan_darwin.go. recoverDaemons is the only caller that uses the vars;
// the normal start path calls the concrete functions directly.
var (
	startDNSFilterFn     = startDNSFilter
	startHTTPFilterFn    = startHTTPFilter
	startMonitorDaemonFn = startMonitorDaemon
	applyFilteredFn      = instance.ApplyFiltered
)

// recoverDaemons restarts any filter or monitor daemons that died while the VM
// was still running. It calls each startXxx wrapper, which is idempotent: alive
// daemons are detected via PID-based liveness and left alone; dead ones have
// their stale socket/PID files cleaned up and a fresh daemon spawned. Per-VM
// resource setup (port reconciliation, cloud-init, VM redefine) is intentionally
// skipped — that is baked into the running VM and must not be touched.
//
// Host egress enforcement, however, lives OUTSIDE the VM: the host iptables
// rules (DNS REDIRECT + accepts) can be flushed out from under a running guest
// (host firewall reload/reboot), silently bypassing the DNS allowlist. So we
// re-assert it here via ApplyFiltered (Define+Apply are idempotent and no-op
// when the rule set is already in force).
func recoverDaemons(w io.Writer, be backend.Backend, name string, inst *config.Instance, paths *config.Paths, brief bool) error {
	if err := startDNSFilterFn(w, name, paths, inst.DNS.LogLevel); err != nil {
		return fmt.Errorf("failed to recover DNS filter: %w", err)
	}
	if err := startHTTPFilterFn(w, name, paths, inst.HTTP.LogLevel); err != nil {
		return fmt.Errorf("failed to recover HTTP filter: %w", err)
	}
	if inst.Monitor.Enabled {
		if err := startMonitorDaemonFn(w, name, paths); err != nil {
			return fmt.Errorf("failed to recover monitor daemon: %w", err)
		}
	}
	// Re-assert host egress rules (only for backends that enforce egress).
	if be.EgressController() != nil {
		if err := applyFilteredFn(w, name, be, brief); err != nil {
			return fmt.Errorf("failed to re-assert egress enforcement: %w", err)
		}
	}
	if inst.Monitor.Enabled {
		warnIfMonitorSocketInaccessible(w, paths)
	}
	return nil
}

// startFilters starts DNS and HTTP filter daemons and sets up their resources.
func startFilters(ctx context.Context, w io.Writer, f *factory.Factory, be backend.Backend, name string, inst *config.Instance, paths *config.Paths) error {
	// Start dnsfilter daemon
	fmt.Fprintln(w, "Starting DNS filter...")
	if err := startDNSFilter(w, name, paths, inst.DNS.LogLevel); err != nil {
		return fmt.Errorf("failed to start DNS filter: %w", err)
	}

	// Query dnsfilter for actual port and update resources
	if err := setupDNSResources(w, f, inst, paths); err != nil {
		return fmt.Errorf("failed to set up DNS resources: %w", err)
	}

	// Start httpfilter daemon
	fmt.Fprintln(w, "Starting HTTP filter...")
	if err := startHTTPFilter(w, name, paths, inst.HTTP.LogLevel); err != nil {
		return fmt.Errorf("failed to start HTTP filter: %w", err)
	}

	// Query httpfilter for actual port and update resources
	if err := setupHTTPResources(ctx, w, f, be, inst, paths); err != nil {
		return fmt.Errorf("failed to set up HTTP resources: %w", err)
	}

	return nil
}

// startVMAndApplyFilter starts the monitor daemon (if enabled), boots the VM,
// and applies the nwfilter to enforce traffic rules.
func startVMAndApplyFilter(ctx context.Context, w io.Writer, be backend.Backend, name string, inst *config.Instance, paths *config.Paths) error {
	// Start monitor daemon (if enabled)
	if inst.Monitor.Enabled {
		fmt.Fprintln(w, "Starting monitor daemon...")
		if err := startMonitorDaemon(w, name, paths); err != nil {
			// Monitor was explicitly enabled - failure should be fatal
			// so the user knows their security monitoring isn't working
			return fmt.Errorf("failed to start monitor daemon: %w", err)
		}
	}

	// Re-assert the VM process's access to the disk/base/ISO before boot. ACLs
	// granted at create/import can be lost out-of-band (filesystem remount without
	// `acl`, restore-from-backup), which would otherwise fail QEMU at start.
	if err := be.Disk().EnsureAccess(ctx, inst, paths); err != nil {
		return fmt.Errorf("failed to ensure disk access: %w", err)
	}

	// Start VM
	fmt.Fprintln(w, "Starting VM...")
	if err := be.VM().Start(ctx, name); err != nil {
		return fmt.Errorf("failed to start VM: %w", err)
	}

	// Apply egress policy to the running VM so traffic rules are enforced. This
	// runs AFTER the VM is up, so a failure here would otherwise leave a running
	// but unfiltered guest — on macOS the per-instance pf anchor is the ONLY
	// egress enforcement. Fail closed: force-stop the VM before surfacing the
	// error so a sandbox is never left running without its traffic filter.
	if ec := be.EgressController(); ec != nil {
		fmt.Fprintln(w, "Applying network filter...")
		if err := ec.Apply(ctx, inst); err != nil {
			failClosedStopVM(ctx, w, be, name)
			return fmt.Errorf("failed to apply egress policy: %w", err)
		}
	}

	// Heads-up if the (now VM-created) monitor socket is not group-accessible, so
	// the user isn't left with silent zero-event monitoring. No-op off Linux.
	if inst.Monitor.Enabled {
		warnIfMonitorSocketInaccessible(w, paths)
	}

	return nil
}

// failClosedStopVM force-stops the VM after egress enforcement could not be
// installed, so the user is never left with a running but unfiltered sandbox.
// It is best-effort: a force-stop failure is logged and reported to the user but
// does not replace the original (more actionable) egress error. Filter and
// monitor daemons spawned earlier in the start flow are left running — they are
// inert without a VM to filter, and `abox stop <name>` reaps them; killing them
// here would add failure modes without closing the security gap.
func failClosedStopVM(ctx context.Context, w io.Writer, be backend.Backend, name string) {
	fmt.Fprintln(w, "Stopping VM to keep the sandbox closed...")
	if err := be.VM().ForceStop(ctx, name); err != nil {
		logging.Warn("failed to stop VM after egress setup failed; instance may be running without traffic filtering", "instance", name, "error", err)
		fmt.Fprintf(w, "Warning: could not stop VM %q (%v); run `abox stop %s` to ensure it is not running unfiltered\n", name, err, name)
	}
}

// waitForReady waits for the guest to become reachable over SSH so the "started"
// message reflects a booted guest. The IP itself is static and deterministic
// (config.IPAddress, baked into cloud-init — no DHCP), so this gates purely on
// reachability. It returns the IP (always) and whether SSH became reachable within
// the timeout; a timeout is reported to the user but does not fail the start.
func waitForReady(w io.Writer, inst *config.Instance, paths *config.Paths) (string, bool) {
	ip := inst.IPAddress
	fmt.Fprint(w, "Waiting for VM to boot...")
	logging.Debug("waiting for VM SSH readiness", "instance", inst.Name, "ip", ip)
	if err := sshutil.WaitForSSH(paths, inst.GetUser(), ip, 90*time.Second); err != nil {
		fmt.Fprintln(w)
		logging.Debug("VM not reachable within timeout", "instance", inst.Name, "ip", ip, "error", err)
		return ip, false
	}
	fmt.Fprintln(w)
	logging.Debug("VM reachable", "instance", inst.Name, "ip", ip)
	return ip, true
}

func startDNSFilter(w io.Writer, name string, paths *config.Paths, logLevel string) error {
	return startFilter(w, name, FilterDNS, FilterPaths{
		Socket:  paths.DNSSocket,
		Log:     paths.DNSServiceLog,
		PIDFile: paths.DNSPIDFile,
	}, logLevel)
}

func startHTTPFilter(w io.Writer, name string, paths *config.Paths, logLevel string) error {
	return startFilter(w, name, FilterHTTP, FilterPaths{
		Socket:  paths.HTTPSocket,
		Log:     paths.HTTPServiceLog,
		PIDFile: paths.HTTPPIDFile,
	}, logLevel)
}

// startMonitorDaemon starts the monitor daemon for an instance.
func startMonitorDaemon(w io.Writer, name string, paths *config.Paths) error {
	return startDaemon(w, name, "monitor", DaemonPaths{
		Socket:  paths.MonitorRPCSocket,
		PIDFile: paths.MonitorPIDFile,
	})
}

// setupDNSResources queries dnsfilter for the actual port and updates config.
// This handles the case where dnsfilter auto-allocates a port (port 0 in config).
func setupDNSResources(w io.Writer, f *factory.Factory, inst *config.Instance, paths *config.Paths) error {
	if f == nil {
		return errors.New("factory not available")
	}

	// Connect to dnsfilter to get actual port
	dnsClient, err := f.DNSClient(inst.Name)
	if err != nil {
		return fmt.Errorf("failed to connect to dnsfilter: %w", err)
	}

	// Retry the Status RPC to handle the race between the socket file appearing
	// (net.Listen) and the gRPC server being ready to serve (grpc.Serve).
	var status *rpc.DNSStatus
	for attempt := range 10 {
		if attempt > 0 {
			time.Sleep(200 * time.Millisecond)
		}
		ctx, cancel := dnsfilter.ClientContext()
		status, err = dnsClient.Status(ctx, &rpc.Empty{})
		cancel()
		if err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("failed to get dnsfilter status: %w", err)
	}

	actualPort := int(status.DnsPort)
	if actualPort == 0 {
		return errors.New("dnsfilter returned port 0")
	}

	// If port changed from config, update resources
	if actualPort != inst.DNS.Port {
		fmt.Fprintf(w, "  DNS port auto-allocated: %d\n", actualPort)
		inst.DNS.Port = actualPort
		if err := config.Save(inst, paths); err != nil {
			logging.Warn("failed to save DNS port to config", "error", err, "instance", inst.Name)
		}
	}

	return nil
}

// setupHTTPResources queries httpfilter for the actual port and updates cloud-init and nwfilter.
// This handles the case where httpfilter auto-allocates a port (port 0 in config).
func setupHTTPResources(ctx context.Context, w io.Writer, f *factory.Factory, be backend.Backend, inst *config.Instance, paths *config.Paths) error {
	if f == nil {
		return errors.New("factory not available")
	}

	if err := resolveHTTPPort(w, f, inst, paths); err != nil {
		return err
	}

	if err := generateCloudInit(ctx, w, be, inst, paths); err != nil {
		return err
	}

	if err := redefineVM(ctx, w, be, inst, paths); err != nil {
		return err
	}

	// Define/update egress policy with actual ports (always do this to ensure it exists)
	fmt.Fprintln(w, "  Defining network filter...")
	if ec := be.EgressController(); ec != nil {
		if err := ec.Define(ctx, inst, backend.BuildEgressPolicy(inst)); err != nil {
			return fmt.Errorf("failed to define egress policy: %w", err)
		}
	}

	return nil
}

// resolveHTTPPort queries httpfilter for the actual port and updates config if needed.
func resolveHTTPPort(w io.Writer, f *factory.Factory, inst *config.Instance, paths *config.Paths) error {
	// Connect to httpfilter to get actual port
	httpClient, err := f.HTTPClient(inst.Name)
	if err != nil {
		return fmt.Errorf("failed to connect to httpfilter: %w", err)
	}

	// Retry the Status RPC to handle the race between the socket file appearing
	// (net.Listen) and the gRPC server being ready to serve (grpc.Serve).
	var status *rpc.HTTPStatus
	for attempt := range 15 {
		if attempt > 0 {
			time.Sleep(300 * time.Millisecond)
		}
		ctx, cancel := httpfilter.ClientContext()
		status, err = httpClient.Status(ctx, &rpc.Empty{})
		cancel()
		if err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("failed to get httpfilter status: %w", err)
	}

	actualPort := int(status.HttpPort)
	if actualPort == 0 {
		return errors.New("httpfilter returned port 0")
	}

	// If port changed from config, update resources
	if actualPort != inst.HTTP.Port {
		fmt.Fprintf(w, "  HTTP port auto-allocated: %d\n", actualPort)
		inst.HTTP.Port = actualPort
		if err := config.Save(inst, paths); err != nil {
			logging.Warn("failed to save HTTP port to config", "error", err, "instance", inst.Name)
		}
	}

	return nil
}

// generateCloudInit generates the cloud-init ISO with actual ports and monitor configuration.
func generateCloudInit(ctx context.Context, w io.Writer, be backend.Backend, inst *config.Instance, paths *config.Paths) error {
	fmt.Fprintln(w, "  Generating cloud-init ISO...")

	// Read CA certificate if it exists (for TLS MITM)
	var caCert string
	if caCertBytes, readErr := os.ReadFile(paths.CACert); readErr == nil {
		caCert = strings.TrimSpace(string(caCertBytes))
	} else if !os.IsNotExist(readErr) {
		return fmt.Errorf("failed to read CA certificate: %w", readErr)
	}

	// Defensive guard for instances that reached this backend without going
	// through create's check (e.g. imported configs): a backend with no monitor
	// transport (vfkit on macOS) cannot honor monitor.enabled. Fail fast with an
	// actionable error instead of the opaque "monitor guest device is empty" that
	// cloud-init generation would otherwise surface.
	if inst.Monitor.Enabled && be.MonitorTransport() == nil {
		return fmt.Errorf("the %s backend does not support security monitoring; set monitor.enabled: false", be.Name())
	}

	// The monitor agent writes events to a backend-specific guest device
	// (virtio-serial on libvirt, a serial tty on VMware); the transport supplies it.
	var monitorDevice string
	if mt := be.MonitorTransport(); mt != nil {
		monitorDevice = mt.GuestDevice()
	}

	// Build contributors for cloud-init generation
	monitorContributor := &monitor.CloudInitContributor{
		Enabled:     inst.Monitor.Enabled,
		KprobeMulti: inst.Monitor.KprobeMulti,
		Kprobes:     inst.Monitor.Kprobes,
		Policies:    inst.Monitor.Policies,
		GuestDevice: monitorDevice,
	}

	if inst.Monitor.Enabled {
		if err := prepareTetragon(ctx, w, paths, monitorContributor, inst.Monitor.Version); err != nil {
			return err
		}
	}

	contributors := []cloudinit.Contributor{
		&cloudinit.DNSContributor{Gateway: inst.Gateway},
		&cloudinit.ProxyContributor{Gateway: inst.Gateway, HTTPPort: inst.HTTP.Port, CACert: caCert},
		monitorContributor,
	}

	if err := cloudinit.GenerateAndInstall(inst, paths, contributors); err != nil {
		return fmt.Errorf("failed to generate cloud-init ISO: %w", err)
	}

	return nil
}

// prepareTetragon fetches and caches the Tetragon release tarball for cloud-init.
func prepareTetragon(ctx context.Context, w io.Writer, paths *config.Paths, contrib *monitor.CloudInitContributor, version string) error {
	fmt.Fprintln(w, "  Preparing Tetragon...")

	release, err := tetragon.GetRelease(ctx, version, false)
	if err != nil {
		return fmt.Errorf("failed to get Tetragon release info: %w", err)
	}
	fmt.Fprintf(w, "  Using Tetragon %s\n", release.Version)

	tarball, err := cloudinit.EnsureTetragonCached(ctx, w, paths.TetragonCache, release)
	if err != nil {
		return fmt.Errorf("failed to cache Tetragon tarball: %w", err)
	}
	contrib.TetragonTarball = tarball
	contrib.TetragonVersion = release.Version
	return nil
}

// redefineVM redefines the domain to include the CDROM device now that the ISO exists.
func redefineVM(ctx context.Context, w io.Writer, be backend.Backend, inst *config.Instance, paths *config.Paths) error {
	fmt.Fprintln(w, "  Updating VM configuration...")
	vmOpts := backend.VMCreateOptions{
		MonitorEnabled: inst.Monitor.Enabled,
		UUID:           be.VM().GetUUID(inst.Name),
	}

	// Load custom domain template if one is stored for this instance.
	// Re-validate on each start: the stored template could have been edited in-place,
	// and validation is cheap compared to the cost of a failed virsh define.
	if tv, ok := be.(backend.TemplateValidator); ok && tv.HasCustomTemplate(inst) {
		fmt.Fprintln(w, "  Using custom domain template (default VM hardening may be bypassed)")
		content, err := tv.LoadCustomTemplate(paths)
		if err != nil {
			return err
		}
		if err := tv.ValidateCustomTemplate(content); err != nil {
			return fmt.Errorf("custom domain template is invalid: %w", err)
		}
		vmOpts.CustomTemplate = content
	}
	if err := be.VM().Redefine(ctx, inst, paths, vmOpts); err != nil {
		return fmt.Errorf("failed to update domain: %w", err)
	}
	return nil
}
