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
	"github.com/sandialabs/abox/internal/firewall"
	"github.com/sandialabs/abox/internal/httpfilter"
	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/monitor"
	"github.com/sandialabs/abox/internal/rpc"
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

	// Get the backend for this instance
	be, err := opts.Factory.BackendFor(name)
	if err != nil {
		return fmt.Errorf("failed to get backend: %w", err)
	}

	w := opts.out()

	// Check if already running
	if be.VM().IsRunning(name) {
		fmt.Fprintf(w, "Instance %q is already running.\n", name)
		return nil
	}

	if err := ensureNetwork(ctx, w, be, inst); err != nil {
		return err
	}

	if err := startFilters(ctx, w, opts.Factory, be, name, inst, paths); err != nil {
		return err
	}

	if err := setupHostFirewall(w, opts.Factory, inst, name); err != nil {
		return err
	}

	if err := startVMAndApplyFilter(ctx, w, be, name, inst, paths); err != nil {
		return err
	}

	ip := waitForIP(w, be, name)

	if !opts.Brief {
		ipInfo := " (IP not yet available)"
		if ip != "" {
			ipInfo = " at " + ip
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
func ensureNetwork(ctx context.Context, w io.Writer, be backend.Backend, inst *config.Instance) error {
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

// startFilters starts DNS and HTTP filter daemons and sets up their resources.
func startFilters(ctx context.Context, w io.Writer, f *factory.Factory, be backend.Backend, name string, inst *config.Instance, paths *config.Paths) error {
	// Start dnsfilter daemon
	fmt.Fprintln(w, "Starting DNS filter...")
	if err := startDNSFilter(name, paths, inst.DNS.LogLevel); err != nil {
		return fmt.Errorf("failed to start DNS filter: %w", err)
	}

	// Query dnsfilter for actual port and update resources
	if err := setupDNSResources(w, f, inst, paths); err != nil {
		return fmt.Errorf("failed to set up DNS resources: %w", err)
	}

	// Start httpfilter daemon
	fmt.Fprintln(w, "Starting HTTP filter...")
	if err := startHTTPFilter(name, paths, inst.HTTP.LogLevel); err != nil {
		return fmt.Errorf("failed to start HTTP filter: %w", err)
	}

	// Query httpfilter for actual port and update resources
	if err := setupHTTPResources(ctx, w, f, be, inst, paths); err != nil {
		return fmt.Errorf("failed to set up HTTP resources: %w", err)
	}

	return nil
}

// setupHostFirewall sets up iptables DNS redirect and configures UFW.
func setupHostFirewall(w io.Writer, f *factory.Factory, inst *config.Instance, name string) error {
	// Set up iptables DNS redirect — this is security-critical because without
	// the PREROUTING redirect, DNS queries bypass the dnsfilter entirely.
	if err := setupIptablesRedirect(w, f, inst); err != nil {
		return fmt.Errorf("failed to set up iptables DNS redirect: %w", err)
	}

	// Configure UFW if active
	if err := configureUFW(w, f, inst); err != nil {
		logging.Warn("failed to configure UFW", "error", err, "instance", name)
	}

	return nil
}

// startVMAndApplyFilter starts the monitor daemon (if enabled), boots the VM,
// and applies the nwfilter to enforce traffic rules.
func startVMAndApplyFilter(ctx context.Context, w io.Writer, be backend.Backend, name string, inst *config.Instance, paths *config.Paths) error {
	// Start monitor daemon (if enabled)
	if inst.Monitor.Enabled {
		fmt.Fprintln(w, "Starting monitor daemon...")
		if err := startMonitorDaemon(name, paths); err != nil {
			// Monitor was explicitly enabled - failure should be fatal
			// so the user knows their security monitoring isn't working
			return fmt.Errorf("failed to start monitor daemon: %w", err)
		}
	}

	// Start VM
	fmt.Fprintln(w, "Starting VM...")
	if err := be.VM().Start(ctx, name); err != nil {
		return fmt.Errorf("failed to start VM: %w", err)
	}

	// Apply nwfilter to the running VM so traffic rules are enforced
	if ti := be.TrafficInterceptor(); ti != nil {
		fmt.Fprintln(w, "Applying network filter...")
		rnames := be.ResourceNames(name)
		if err := ti.ApplyFilter(ctx, name, inst.Bridge, rnames.Filter, inst.MACAddress, inst.CPUs); err != nil {
			return fmt.Errorf("failed to apply network filter: %w", err)
		}
	}

	return nil
}

// waitForIP polls for the VM's IP address, returning it when available or empty after timeout.
func waitForIP(w io.Writer, be backend.Backend, name string) string {
	fmt.Fprint(w, "Waiting for VM to boot")
	logging.Debug("waiting for VM IP", "instance", name)
	var ip string
	for i := range 60 {
		time.Sleep(time.Second)
		fmt.Fprint(w, ".")
		if addr, err := be.VM().GetIP(name); err == nil {
			ip = addr
			logging.Debug("VM IP obtained", "instance", name, "ip", ip, "attempts", i+1)
			break
		}
	}
	fmt.Fprintln(w)
	return ip
}

func startDNSFilter(name string, paths *config.Paths, logLevel string) error {
	return startFilter(name, FilterDNS, FilterPaths{
		Socket:  paths.DNSSocket,
		Log:     paths.DNSServiceLog,
		PIDFile: paths.DNSPIDFile,
	}, logLevel)
}

func startHTTPFilter(name string, paths *config.Paths, logLevel string) error {
	return startFilter(name, FilterHTTP, FilterPaths{
		Socket:  paths.HTTPSocket,
		Log:     paths.HTTPServiceLog,
		PIDFile: paths.HTTPPIDFile,
	}, logLevel)
}

// startMonitorDaemon starts the monitor daemon for an instance.
func startMonitorDaemon(name string, paths *config.Paths) error {
	return startDaemon(name, "monitor", DaemonPaths{
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

	if err := generateCloudInit(ctx, w, f, inst, paths); err != nil {
		return err
	}

	if err := redefineVM(ctx, w, be, inst, paths); err != nil {
		return err
	}

	// Define/update nwfilter with actual ports (always do this to ensure filter exists)
	fmt.Fprintln(w, "  Defining network filter...")
	if ti := be.TrafficInterceptor(); ti != nil {
		if err := ti.DefineFilter(ctx, inst); err != nil {
			return fmt.Errorf("failed to define network filter: %w", err)
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
func generateCloudInit(ctx context.Context, w io.Writer, f *factory.Factory, inst *config.Instance, paths *config.Paths) error {
	fmt.Fprintln(w, "  Generating cloud-init ISO...")
	client, err := f.PrivilegeClientFor(inst.Name)
	if err != nil {
		return fmt.Errorf("failed to get privilege client: %w", err)
	}

	// Read CA certificate if it exists (for TLS MITM)
	var caCert string
	if caCertBytes, readErr := os.ReadFile(paths.CACert); readErr == nil {
		caCert = strings.TrimSpace(string(caCertBytes))
	} else if !os.IsNotExist(readErr) {
		return fmt.Errorf("failed to read CA certificate: %w", readErr)
	}

	// Build contributors for cloud-init generation
	monitorContributor := &monitor.CloudInitContributor{
		Enabled:     inst.Monitor.Enabled,
		KprobeMulti: inst.Monitor.KprobeMulti,
		Kprobes:     inst.Monitor.Kprobes,
		Policies:    inst.Monitor.Policies,
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

	if err := cloudinit.GenerateAndInstall(client, inst, paths, contributors); err != nil {
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

// configureUFW adds a UFW rule to allow traffic on the instance's bridge interface.
// This is only done if UFW is installed and active. Errors are non-fatal.
func configureUFW(w io.Writer, f *factory.Factory, inst *config.Instance) error {
	if f == nil {
		return nil
	}

	client, err := f.PrivilegeClientFor(inst.Name)
	if err != nil {
		return err
	}

	ufwClient := firewall.NewUFWClient(client)
	if !ufwClient.IsActive() {
		return nil
	}

	fmt.Fprintln(w, "Configuring UFW rules...")
	return ufwClient.Allow(inst.Bridge)
}

// setupIptablesRedirect adds iptables NAT rules to redirect DNS traffic (port 53)
// to the dnsfilter service. This is necessary because systemd-resolved always
// connects to port 53, so we use iptables PREROUTING to redirect to the actual
// dnsfilter port.
func setupIptablesRedirect(w io.Writer, f *factory.Factory, inst *config.Instance) error {
	if f == nil {
		return errors.New("factory not available")
	}

	client, err := f.PrivilegeClientFor(inst.Name)
	if err != nil {
		return fmt.Errorf("failed to get privilege client: %w", err)
	}

	fmt.Fprintln(w, "Setting up DNS redirect...")
	iptablesClient := firewall.NewIPTablesClient(client)
	return iptablesClient.AddDNSRedirect(inst)
}
