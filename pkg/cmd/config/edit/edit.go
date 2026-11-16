package edit

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/daemon"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/validation"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// libvirtBackendName gates --subnet: only the libvirt backend derives a
// persistent host-side network object from Instance.Subnet that abox owns and
// can recreate on demand; vfkit and vmware manage their own networks.
const libvirtBackendName = "libvirt"

// daemonAlive reports whether a PID file names a live abox daemon process (the
// same liveness check `abox start` uses before skipping a spawn). Package
// variable so unit tests can stub liveness without spawning daemons.
var daemonAlive = daemon.AliveByPIDFile

// Options holds the options for the edit command.
type Options struct {
	Factory  *factory.Factory
	CPUs     int
	Memory   int
	Disk     string
	Upstream string
	Subnet   string
	Name     string
}

// NewCmdEdit creates a new config edit command.
func NewCmdEdit(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "edit <instance>",
		Short: "Edit instance configuration",
		Long: `Edit the configuration for an abox instance.

Only the following fields can be modified:
  --cpus      Number of CPUs (requires VM restart)
  --memory    Memory in MB (requires VM restart)
  --disk      Disk size (can only grow, not shrink)
  --upstream  Upstream DNS server (requires dnsfilter restart)
  --subnet    IP subnet (libvirt only; the instance must be stopped;
              takes effect on the next start)

Fields like bridge and ports cannot be changed after instance creation.`,
		Example: `  abox config edit dev --cpus 4            # Change CPU count
  abox config edit dev --memory 8192       # Change memory (MB)
  abox config edit dev -c 4 -m 8192       # Change multiple fields at once
  abox config edit dev --subnet 10.77.0.0/24  # Move a stopped instance to a new /24`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completion.Sequence(completion.AllInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if runF != nil {
				return runF(opts)
			}
			return runEdit(cmd, opts, args[0])
		},
	}

	cmd.Flags().IntVarP(&opts.CPUs, "cpus", "c", 0, "Number of CPUs")
	cmd.Flags().IntVarP(&opts.Memory, "memory", "m", 0, "Memory in MB")
	cmd.Flags().StringVar(&opts.Disk, "disk", "", "Disk size (e.g., 30G)")
	cmd.Flags().StringVarP(&opts.Upstream, "upstream", "u", "", "Upstream DNS server")
	cmd.Flags().StringVar(&opts.Subnet, "subnet", "", "IP subnet in CIDR /24 notation (libvirt only; instance must be stopped)")

	return cmd
}

func runEdit(cmd *cobra.Command, opts *Options, name string) error {
	if !config.Exists(name) {
		return fmt.Errorf("instance %q does not exist", name)
	}

	inst, paths, err := config.Load(name)
	if err != nil {
		return err
	}

	// The lock serializes this edit against other config writers — in particular
	// a concurrent `abox create` allocating subnets. For --subnet it covers
	// validate -> network delete -> config.Save (the deferred release runs at
	// function exit, after Save), so no concurrent allocation can grab the new
	// /24 between its validation and persistence.
	if err := config.AcquireLock(); err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = config.ReleaseLock() }()

	changes, err := applyChanges(cmd, opts, inst, paths)
	if err != nil {
		return err
	}

	if err := config.Save(inst, paths); err != nil {
		return err
	}

	w := opts.Factory.IO.Out
	fmt.Fprintf(w, "Updated %s:\n", name)
	for _, c := range changes {
		fmt.Fprintf(w, "  %s\n", c)
	}

	logging.AuditInstance(name, logging.ActionConfigEdit, "changes", strings.Join(changes, "; "))

	return nil
}

// applyChanges validates every requested flag change and mutates inst in place,
// returning the human-readable change descriptions. Split from runEdit to keep
// each function's cognitive complexity within the lint budget. The caller holds
// the config lock and persists inst afterwards.
func applyChanges(cmd *cobra.Command, opts *Options, inst *config.Instance, paths *config.Paths) ([]string, error) {
	var changes []string

	if cmd.Flags().Changed("cpus") {
		if err := validation.ValidateResourceLimits(opts.CPUs, inst.Memory); err != nil {
			return nil, cmdutil.FlagErrorf("%s", err)
		}
		changes = append(changes, fmt.Sprintf("cpus: %d -> %d", inst.CPUs, opts.CPUs))
		inst.CPUs = opts.CPUs
	}

	if cmd.Flags().Changed("memory") {
		if err := validation.ValidateResourceLimits(inst.CPUs, opts.Memory); err != nil {
			return nil, cmdutil.FlagErrorf("%s", err)
		}
		changes = append(changes, fmt.Sprintf("memory: %d -> %d MB", inst.Memory, opts.Memory))
		inst.Memory = opts.Memory
	}

	if cmd.Flags().Changed("disk") {
		if err := validation.ValidateDiskSize(opts.Disk); err != nil {
			return nil, cmdutil.FlagErrorf("%s", err)
		}
		if err := validateDiskSize(opts.Disk, inst.Disk); err != nil {
			return nil, err
		}
		changes = append(changes, fmt.Sprintf("disk: %s -> %s", inst.Disk, opts.Disk))
		inst.Disk = opts.Disk
	}

	if cmd.Flags().Changed("upstream") {
		normalized, err := validation.NormalizeUpstreamDNS(opts.Upstream)
		if err != nil {
			return nil, fmt.Errorf("invalid upstream DNS: %w", err)
		}
		changes = append(changes, fmt.Sprintf("dns.upstream: %s -> %s", inst.DNS.Upstream, normalized))
		inst.DNS.Upstream = normalized
	}

	if cmd.Flags().Changed("subnet") {
		change, err := subnetChange(cmd.Context(), opts, inst, paths)
		if err != nil {
			return nil, err
		}
		changes = append(changes, change)
	}

	if len(changes) == 0 {
		return nil, cmdutil.FlagErrorf("no changes specified; use --cpus, --memory, --disk, --upstream, or --subnet")
	}

	return changes, nil
}

// subnetChange resolves the instance's backend and applies the --subnet edit.
func subnetChange(ctx context.Context, opts *Options, inst *config.Instance, paths *config.Paths) (string, error) {
	be, err := opts.Factory.BackendFor(opts.Name)
	if err != nil {
		return "", err
	}
	return editSubnet(ctx, opts, be, inst, paths)
}

// editSubnet validates and applies a subnet change for a stopped libvirt
// instance, mutating inst's Subnet/Gateway/IPAddress in place and returning the
// change description; the caller persists via config.Save. It deletes the stale
// libvirt network (defined from the old subnet) so the next `abox start`
// re-creates it from the new one — everything else already regenerates per
// start: the cloud-init ISO is rebuilt with a fresh instance-id (so the guest
// re-renders its MAC-matched static-IP netplan), and the nwfilter/host firewall
// rules are rebuilt from BuildEgressPolicy. Bridge and MAC are left unchanged
// and the domain XML references only those, so no VM redefine is needed.
//
// The caller must hold the config lock (config.AcquireLock) across this call
// and the subsequent config.Save.
func editSubnet(ctx context.Context, opts *Options, be backend.Backend, inst *config.Instance, paths *config.Paths) (string, error) {
	// Backend gate first, so e.g. a vfkit user gets the real reason (subnet is
	// not editable there at all) rather than an incidental "already X" no-op.
	if be.Name() != libvirtBackendName {
		return "", fmt.Errorf("subnet can only be edited on the libvirt backend; the %s backend manages its own networks", be.Name())
	}

	if opts.Subnet == inst.Subnet {
		return "", cmdutil.FlagErrorf("subnet is already %s", inst.Subnet)
	}

	// A stopped instance is required for two reasons: net-destroy on a bridge
	// with a live VM attached is destructive (it yanks the guest's NIC out from
	// under it), and stop's cleanupAfterStop removes host egress rules keyed on
	// the CURRENT config — editing while running would strand the old-subnet
	// rules when the instance is eventually stopped.
	if be.VM().IsRunning(inst.Name) {
		return "", fmt.Errorf("instance %q is running; stop it before changing the subnet", inst.Name)
	}

	// The filter daemons can outlive a stopped VM: a failed `abox start`
	// deliberately leaves them running after force-stopping the VM, and
	// out-of-band VM death doesn't reap them either. They bind the GATEWAY IP
	// (filterbase.DNSListenAddress/HTTPListenAddress) and start skips spawning
	// when a daemon is already alive — so editing the subnet under live daemons
	// would leave old-gateway-bound filters serving a guest pointed at the new
	// gateway. Reject rather than reap to keep the edit non-destructive. (The
	// monitor daemon is unaffected: it talks virtio-serial + unix sockets and
	// never binds the gateway.)
	if slices.ContainsFunc([]string{paths.DNSPIDFile, paths.HTTPPIDFile}, daemonAlive) {
		return "", fmt.Errorf("instance %q has filter daemons running (likely from a failed start); run 'abox stop %s' first", inst.Name, inst.Name)
	}

	gateway, _, err := config.ValidateSubnet(opts.Subnet)
	if err != nil {
		return "", err
	}

	// Warn (never fail -- it's a deliberate override) when the host already routes
	// the chosen subnet elsewhere (e.g. a VPN split-include), which would leave the
	// guest unreachable from the host. Same wording as `abox create --subnet`.
	// No-op under test (RouteConflicts defaults to a no-op unless the binary wired
	// the real prober).
	if config.RouteConflicts(gateway) {
		cs := opts.Factory.ColorScheme
		errOut := opts.Factory.IO.ErrOut
		fmt.Fprintln(errOut, cs.Yellow(cs.Bold("WARNING:"))+cs.Yellow(fmt.Sprintf(" subnet %s appears already routed by the host (VPN?).", opts.Subnet)))
		fmt.Fprintln(errOut, cs.Yellow("host-to-guest traffic (SSH, mount) may be unreachable. Choose a different"))
		fmt.Fprintln(errOut, cs.Yellow("--subnet or disconnect the VPN."))
	}

	// Delete the stale libvirt network BEFORE saving the new subnet: it was
	// defined from the old gateway and `abox start` only re-creates it when
	// missing (ensureNetwork). Failing the edit on error keeps config and libvirt
	// from diverging — a saved new-subnet config pointing at a still-defined
	// old-subnet network would silently boot the guest onto the wrong /24. This
	// is net-destroy + net-undefine via unprivileged virsh (no privilege helper).
	if be.Network().Exists(inst.Bridge) {
		if err := be.Network().Delete(ctx, inst.Bridge); err != nil {
			return "", fmt.Errorf("failed to delete network %q for subnet change: %w", inst.Bridge, err)
		}
	}

	oldSubnet := inst.Subnet
	inst.Subnet = opts.Subnet
	inst.Gateway = gateway
	// The guest is always .10 on its /24 (see config.DeriveHostIP); IPAddress
	// seeds the TLS certificate SAN and the host-to-guest fallback address, so it
	// must track the subnet.
	inst.IPAddress = config.DeriveHostIP(gateway)

	return fmt.Sprintf("subnet: %s -> %s (guest IP %s, applied on next start)", oldSubnet, inst.Subnet, inst.IPAddress), nil
}

// validateDiskSize checks that the new disk size is valid and not smaller than
// current. The new size is already format-validated by validation.ValidateDiskSize
// before this runs; here we only compare byte counts via the shared parser.
func validateDiskSize(newSize, currentSize string) error {
	newBytes, err := validation.ParseDiskSize(newSize)
	if err != nil {
		return fmt.Errorf("invalid disk size %q: %w", newSize, err)
	}

	currentBytes, err := validation.ParseDiskSize(currentSize)
	if err != nil {
		return nil //nolint:nilerr // unparseable current size; skip validation and allow the change
	}

	if newBytes < currentBytes {
		return fmt.Errorf("disk size can only be increased (current: %s)", currentSize)
	}

	return nil
}
