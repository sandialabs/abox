package create

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/boxfile"
	"github.com/sandialabs/abox/internal/cert"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/validation"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// monitorGuestArch is the guest architecture used to gate arch-limited features
// (currently Tetragon monitoring, which ships amd64-only). It mirrors the host
// arch, matching the arch-aware base-image selection in internal/images. It is a
// package variable so tests can exercise the gate deterministically on any host.
var monitorGuestArch = runtime.GOARCH

// Options holds the options for the create command.
type Options struct {
	Factory             *factory.Factory
	CPUs                int
	Memory              int
	Base                string
	Upstream            string
	Disk                string
	Subnet              string
	User                string
	DryRun              bool
	FromFile            string
	TrustBoxfile        string                   // expected abox.yaml fingerprint for non-interactive trust (--trust-boxfile / ABOX_TRUST_BOXFILE)
	Allowlist           []string                 // If non-nil, use these instead of defaults
	MonitorEnabled      bool                     // Enable Tetragon monitoring via virtio-serial
	MonitorVersion      string                   // Tetragon version to use (empty = latest)
	MonitorKprobeMulti  bool                     // Enable BPF kprobe_multi attachment
	MonitorKprobes      []string                 // Curated kprobe names (nil = all defaults)
	MonitorPolicies     []string                 // Absolute paths to custom TracingPolicy YAML files
	MITM                bool                     // Enable TLS MITM for domain fronting protection
	NoMITM              bool                     // Disable TLS MITM (inverted to MITM in runCreate)
	MaxConnections      int                      // HTTP proxy concurrent-connection cap (0/unset = default)
	AllowPrivateTargets []string                 // opt-in CIDRs the filters may reach despite SSRF deny-by-default
	AllowedPorts        []int                    // opt-in destination ports (empty = built-in 443/80+443 defaults)
	SecretInjections    []config.SecretInjection // host-side secret -> outbound header bindings (from abox.yaml)
	MITMExceptions      []string                 // domains tunneled without TLS interception even when MITM is enabled (from abox.yaml)
	Brief               bool                     // Suppress final summary/next-steps output
	TemplateContent     string                   // Custom domain XML template content (from overrides.<backend>.template)
	BackendName         string                   // Preferred VM backend (from abox.yaml backend:); ABOX_BACKEND still wins
	Name                string                   // Instance name (positional arg)
}

// NewCmdCreate creates a new create command.
func NewCmdCreate(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory:        f,
		MITM:           true, // Default to enabled for security
		MaxConnections: config.DefaultHTTPMaxConnections,
	}

	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new abox instance",
		Long: `Create a new isolated sandbox instance.

This will:
  - Allocate a unique subnet and ports
  - Create an isolated network with NAT
  - Create a VM from the base image
  - Set up DNS filtering
  - Generate SSH keys

Use --from-file to read configuration from an abox.yaml file instead of
specifying options on the command line. The instance name can be provided
as an argument (overrides the name in the file) or read from the file.`,
		Example: `  abox create dev                          # Create with defaults
  abox create dev -c 4 -m 8192            # Custom CPUs and memory
  abox create dev -b ubuntu-22.04         # Use a specific base image
  abox create --from-file abox.yaml       # Create from config file
  abox create dev --dry-run               # Preview without creating`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Determine instance name
			if len(args) > 0 {
				opts.Name = args[0]
			}

			// Require name unless --from-file is used
			if opts.Name == "" && opts.FromFile == "" {
				return cmdutil.FlagErrorf("instance name is required (or use --from-file)")
			}

			if runF != nil {
				return runF(opts)
			}
			return Run(cmd.Context(), opts, opts.Name)
		},
	}

	cmd.Flags().IntVarP(&opts.CPUs, "cpus", "c", 2, "Number of CPUs")
	cmd.Flags().IntVarP(&opts.Memory, "memory", "m", 4096, "Memory in MB")
	cmd.Flags().StringVarP(&opts.Base, "base", "b", "ubuntu-24.04", "Base image name")
	cmd.Flags().StringVarP(&opts.Upstream, "upstream", "u", "", "Upstream DNS server (default: host system resolver from /etc/resolv.conf)")
	cmd.Flags().StringVar(&opts.Disk, "disk", "20G", "Disk size")
	cmd.Flags().StringVar(&opts.Subnet, "subnet", "", "Subnet to use (e.g., 192.168.50.0/24)")
	cmd.Flags().StringVar(&opts.User, "user", "", "SSH username (auto-detected from base image if not specified)")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Print generated XML without creating instance")
	cmd.Flags().StringVar(&opts.FromFile, "from-file", "", "Read configuration from abox.yaml file")
	cmd.Flags().StringVar(&opts.TrustBoxfile, "trust-boxfile", "", "Expected abox.yaml security fingerprint; trusts a security-relevant abox.yaml non-interactively (for CI). Source the value from a separately-reviewed channel, not the same checkout.")
	cmd.Flags().BoolVar(&opts.MonitorEnabled, "monitor", false, "Enable Tetragon monitoring via virtio-serial")
	cmd.Flags().StringVar(&opts.MonitorVersion, "monitor-version", "", "Tetragon version to use (empty for latest)")

	cmd.Flags().BoolVar(&opts.NoMITM, "no-mitm", false, "Disable TLS MITM for HTTP proxy")

	return cmd
}

// Run executes the create command with the given options and instance name.
// When opts.FromFile is set the boxfile is loaded and applied here; callers that
// already hold a parsed boxfile (abox up) must use RunFromBoxfile instead so
// there is exactly one abox.yaml -> Options mapping.
func Run(ctx context.Context, opts *Options, name string) error {
	// --no-mitm is inverted BEFORE the boxfile is applied, so a boxfile's mitm:
	// value still wins over the flag. This preserves the historical --from-file
	// precedence, where the file wins for every option; do not move it below
	// applyBoxfile without deciding that flags-beat-file is the new rule for all
	// options, not just this one.
	if opts.NoMITM {
		opts.MITM = false
	}

	var (
		box    *boxfile.Boxfile
		boxDir string
	)
	if opts.FromFile != "" {
		var err error
		var rawYAML []byte
		box, boxDir, rawYAML, err = boxfile.LoadFileRaw(opts.FromFile)
		if err != nil {
			return err
		}
		if err := box.Validate(boxDir); err != nil {
			return err
		}
		// Trust gate: a repo-supplied abox.yaml with security-relevant settings
		// must be confirmed before ANY of its values are acted on — including
		// the --dry-run path and the sudo/privilege prompt in executeCreate.
		// `abox up` runs the same gate itself (see runUp) before calling
		// RunFromBoxfile, so the gate fires exactly once on either path.
		trustToken := opts.TrustBoxfile
		if trustToken == "" {
			trustToken = os.Getenv("ABOX_TRUST_BOXFILE")
		}
		if err := cmdutil.TrustBoxfile(opts.Factory.IO, opts.Factory.Prompter, opts.Factory.ColorScheme, box, rawYAML, boxDir, trustToken); err != nil {
			return err
		}
		// Name from arg takes precedence
		if name == "" {
			name = box.Name
		}
		if err := applyBoxfile(opts, box, boxDir); err != nil {
			return err
		}
	}

	return runCreate(ctx, opts, box, boxDir, name)
}

// RunFromBoxfile creates an instance from an already-parsed abox.yaml. It exists
// so `abox up` does not have to assemble Options itself: the boxfile-derived
// settings all come from applyBoxfile, and backend-dependent ones
// (overrides.<backend>.template) are resolved by runCreate after backend
// detection. box.Name is used as-is, so callers must apply any name suffix
// before calling. Callers are also responsible for the abox.yaml trust gate
// (cmdutil.TrustBoxfile) — abox up runs it in runUp before calling this.
func RunFromBoxfile(ctx context.Context, f *factory.Factory, box *boxfile.Boxfile, boxDir string, brief bool) error {
	opts := &Options{Factory: f, Brief: brief}
	if err := box.Validate(boxDir); err != nil {
		return err
	}
	if err := applyBoxfile(opts, box, boxDir); err != nil {
		return err
	}
	return runCreate(ctx, opts, box, boxDir, box.Name)
}

// cleanupState tracks resources created during instance creation for rollback on failure.
type cleanupState struct {
	backend      backend.Backend
	inst         *config.Instance
	paths        *config.Paths
	out          io.Writer
	configSaved  bool
	sshKeyGen    bool
	caKeyGen     bool
	allowlistGen bool
	networkDef   bool
	networkStart bool
	diskCreated  bool
	domainDef    bool
}

// cleanup removes all created resources. Called on create failure.
func (c *cleanupState) cleanup() {
	if c == nil || c.paths == nil {
		return
	}

	fmt.Fprintln(c.out, "\nCleaning up after failed creation...")

	ctx := context.Background()
	c.cleanupDomain(ctx)
	c.cleanupDisk(ctx)
	c.cleanupNetwork(ctx)
	c.cleanupInstanceData()
}

// cleanupDomain removes the VM definition if it was created.
func (c *cleanupState) cleanupDomain(ctx context.Context) {
	if !c.domainDef || c.inst == nil || c.backend == nil {
		return
	}
	if !c.backend.VM().Exists(c.inst.Name) {
		return
	}
	fmt.Fprintln(c.out, "  Removing VM definition...")
	if err := c.backend.VM().Remove(ctx, c.inst.Name); err != nil {
		logging.Debug("cleanup: failed to remove VM definition", "instance", c.inst.Name, "error", err)
	}
}

// cleanupDisk removes the disk directory. Disk storage is user-owned, so this
// runs unprivileged.
func (c *cleanupState) cleanupDisk(_ context.Context) {
	if !c.diskCreated || c.paths.DiskDir == "" {
		return
	}
	fmt.Fprintln(c.out, "  Removing disk...")
	if err := instance.RemoveDiskDir(c.paths); err != nil {
		logging.Debug("cleanup: failed to remove disk", "path", c.paths.DiskDir, "error", err)
	}
}

// cleanupNetwork removes the network if it was defined or started.
func (c *cleanupState) cleanupNetwork(ctx context.Context) {
	if (!c.networkDef && !c.networkStart) || c.inst == nil || c.backend == nil {
		return
	}
	if !c.backend.Network().Exists(c.inst.Bridge) {
		return
	}
	fmt.Fprintln(c.out, "  Removing network...")
	if err := c.backend.Network().Delete(ctx, c.inst.Bridge); err != nil {
		logging.Debug("cleanup: failed to remove network", "bridge", c.inst.Bridge, "error", err)
	}
}

// cleanupInstanceData removes the config directory (includes SSH keys and allowlist).
func (c *cleanupState) cleanupInstanceData() {
	if (!c.configSaved && !c.sshKeyGen && !c.allowlistGen) || c.inst == nil {
		return
	}
	fmt.Fprintln(c.out, "  Removing instance data...")
	if err := config.Delete(c.inst.Name); err != nil {
		logging.Debug("cleanup: failed to remove instance data", "instance", c.inst.Name, "error", err)
	}
}

// runCreate is the shared body behind Run and RunFromBoxfile. box/boxDir are the
// boxfile this instance came from, or nil/"" for a flags-only create; they are
// carried this far only because overrides.<backend>.template cannot be resolved
// until the backend is detected below. The abox.yaml trust gate has already run
// by this point (in Run for --from-file, in runUp for abox up).
func runCreate(ctx context.Context, opts *Options, box *boxfile.Boxfile, boxDir, name string) error {
	if err := validateCreateInputs(opts, name); err != nil {
		return err
	}

	// Detect backend early so we can use its name for override loading
	// and its storage dir for path computation. A backend: declared in abox.yaml
	// is honored here unless ABOX_BACKEND overrides it.
	//
	// Returned unwrapped: BackendForNew's errors already name the backend and say
	// where the choice came from, and not all of them are detection failures — a
	// "failed to detect backend:" prefix would mislabel the experimental-backend
	// rejection, which is a refusal rather than a failure to find anything.
	be, err := opts.Factory.BackendForNew(opts.BackendName)
	if err != nil {
		return err
	}

	// Reject monitoring on backends that provide no monitor transport (e.g.
	// vfkit on macOS). Fail fast here rather than letting `abox start` die later
	// with an opaque "monitor guest device is empty" error — and never silently
	// disable it, since monitoring is a security feature the user opted into.
	if opts.MonitorEnabled && be.MonitorTransport() == nil {
		return fmt.Errorf("the %s backend does not support security monitoring; set monitor.enabled: false", be.Name())
	}

	// Reject monitoring on non-amd64 hosts. Base-image selection is arch-aware
	// (an arm64 host boots an arm64 guest), but the Tetragon monitor install path
	// currently downloads and extracts an amd64-only binary, which cannot execute
	// in a non-amd64 guest. Fail closed here rather than booting a guest whose
	// opted-in security monitor silently never runs. (Arch-aware Tetragon is a
	// follow-up.)
	if opts.MonitorEnabled && monitorGuestArch != "amd64" {
		return fmt.Errorf("security monitoring (Tetragon) is only supported on amd64 guests, not %s; set monitor.enabled: false", monitorGuestArch)
	}

	// Get paths using the backend's storage directory
	paths, err := config.GetPathsWithStorage(name, be.StorageDir())
	if err != nil {
		return err
	}

	tv, templateSupported := be.(backend.TemplateValidator)

	if err := loadBackendOverrides(opts, box, boxDir, be, templateSupported); err != nil {
		return err
	}

	// A custom template's security impact is surfaced (and confirmed) by the
	// trust gate above, which runs before this point — no separate warning here.

	// Dry-run mode: generate XML with example values and exit
	if opts.DryRun {
		return runDryRun(opts, name, paths, be)
	}

	// Acquire lock to prevent race conditions during resource allocation
	if err := config.AcquireLock(); err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = config.ReleaseLock() }()

	// Check if already exists
	if config.Exists(name) {
		return fmt.Errorf("instance %q already exists", name)
	}

	return executeCreate(ctx, opts, name, paths, be, tv, templateSupported)
}

// executeCreate runs the actual instance creation with cleanup-on-failure semantics.
// This is separated from runCreate to keep the deferred cleanup pattern simple.
func executeCreate(
	ctx context.Context,
	opts *Options,
	name string,
	paths *config.Paths,
	be backend.Backend,
	tv backend.TemplateValidator,
	templateSupported bool,
) (retErr error) {
	w := opts.Factory.IO.Out
	fmt.Fprintf(w, "Creating instance %q...\n", name)
	fmt.Fprintf(w, "  Backend: %s\n", be.Name())

	cs := &cleanupState{
		backend: be,
		paths:   paths,
		out:     w,
	}
	defer func() {
		if retErr != nil {
			cs.cleanup()
		}
	}()

	inst, subnet, err := initInstance(opts, name, paths, be, tv, templateSupported, cs)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "  Subnet: %s (gateway: %s)\n", inst.Subnet, inst.Gateway)

	if err := createInstanceResources(ctx, opts, cs, be, tv, templateSupported, paths, inst, w); err != nil {
		return err
	}

	printCreateSummary(opts, name, inst, subnet, w)

	return nil
}

// initInstance sets up directories, subnet, instance config, and saves it.
// Returns the instance, subnet string, and any error. Instance creation is
// fully unprivileged (disk storage is user-owned).
func initInstance(
	opts *Options,
	name string,
	paths *config.Paths,
	be backend.Backend,
	tv backend.TemplateValidator,
	templateSupported bool,
	cs *cleanupState,
) (*config.Instance, string, error) {
	if err := config.EnsureDirs(paths); err != nil {
		return nil, "", err
	}

	subnet, gateway, err := allocateSubnet(opts, be)
	if err != nil {
		return nil, "", err
	}

	inst := buildInstanceConfig(opts, name, paths, be, gateway, subnet)
	if opts.TemplateContent != "" && templateSupported {
		tv.SetCustomTemplate(inst, true)
	}
	cs.inst = inst

	if err := config.Save(inst, paths); err != nil {
		return nil, "", err
	}
	cs.configSaved = true

	// Store custom domain template if provided.
	if opts.TemplateContent != "" && templateSupported {
		if err := tv.StoreCustomTemplate(paths, opts.TemplateContent); err != nil {
			return nil, "", err
		}
	}

	return inst, subnet, nil
}

// applyBoxfile copies every abox.yaml-derived setting onto opts. This is the
// single mapping from boxfile.Boxfile to create.Options: both
// `abox create --from-file` (via Run) and `abox up` (via RunFromBoxfile) reach
// it, so a key added to abox.yaml cannot be honored by one command and silently
// dropped by the other. It is unexported on purpose — no package outside create
// should be able to express a boxfile mapping.
//
// Boxfile values overwrite whatever the caller put in opts, which is the
// long-standing --from-file precedence (the file wins). See Run for the one
// deliberate exception, --no-mitm.
//
// TemplateContent is deliberately not set here: it comes from
// overrides.<backend>.template and cannot be resolved until the backend is
// known, so loadBackendOverrides handles it after detection.
//
// INVARIANT: every yaml-tagged field of boxfile.Boxfile is either assigned here
// or listed with a reason in knownBoxfileKeys (see boxopts_test.go), which fails
// the build when a new key is added to neither.
func applyBoxfile(opts *Options, box *boxfile.Boxfile, boxDir string) error {
	opts.BackendName = box.Backend
	opts.CPUs = box.CPUs
	opts.Memory = box.Memory
	opts.Base = box.Base
	opts.Upstream = box.DNS.Upstream
	opts.Disk = box.Disk
	opts.Subnet = box.Subnet
	opts.User = box.User
	opts.Allowlist = box.Allowlist
	opts.MonitorEnabled = box.Monitor.Enabled
	opts.MonitorVersion = box.Monitor.Version
	opts.MonitorKprobeMulti = box.GetKprobeMulti()
	opts.MonitorKprobes = box.Monitor.Kprobes
	if len(box.Monitor.Policies) > 0 {
		resolved, err := box.ResolvePolicyPaths(boxDir)
		if err != nil {
			return err
		}
		opts.MonitorPolicies = resolved
	}
	opts.MITM = box.GetMITM()
	opts.MaxConnections = box.GetMaxConnections()
	opts.AllowPrivateTargets = box.GetAllowPrivateTargets()
	opts.AllowedPorts = box.GetAllowedPorts()
	opts.SecretInjections = box.GetSecretInjections()
	opts.MITMExceptions = box.GetMITMExceptions()

	return nil
}

// validateCreateInputs validates the instance name, SSH user, resource limits, disk size,
// and upstream DNS configuration.
func validateCreateInputs(opts *Options, name string) error {
	if err := validation.ValidateInstanceName(name); err != nil {
		return err
	}

	if opts.User != "" {
		if err := validation.ValidateSSHUser(opts.User); err != nil {
			return fmt.Errorf("invalid SSH user: %w", err)
		}
	}

	if err := validation.ValidateResourceLimits(opts.CPUs, opts.Memory); err != nil {
		return err
	}

	if err := validation.ValidateDiskSize(opts.Disk); err != nil {
		return err
	}

	// An empty upstream means "use the host's system resolver" (resolved in
	// dnsfilter.NewServer at daemon start); accept it without normalization.
	if opts.Upstream != "" {
		normalizedUpstream, err := validation.NormalizeUpstreamDNS(opts.Upstream)
		if err != nil {
			return err
		}
		opts.Upstream = normalizedUpstream
	}

	return nil
}

// loadBackendOverrides loads backend-specific overrides from boxfile and validates template support.
func loadBackendOverrides(opts *Options, box *boxfile.Boxfile, boxDir string, be backend.Backend, templateSupported bool) error {
	if box != nil {
		templateContent, err := box.LoadOverrideContent(be.Name(), "template", boxDir)
		if err != nil {
			return err
		}
		opts.TemplateContent = templateContent
	}

	if opts.TemplateContent != "" && !templateSupported {
		return fmt.Errorf("custom templates are not supported by the %s backend", be.Name())
	}

	return nil
}

// allocateSubnet validates or allocates a subnet and returns subnet, gateway, and any error.
// It routes through the backend so a backend that implements
// backend.NetworkDefaulter (e.g. macOS vmnet's host-mode pool) can supply its
// own allocation; libvirt/vmware do not, so they fall back to the shared
// config.AllocateSubnet pool — byte-for-byte unchanged.
func allocateSubnet(opts *Options, be backend.Backend) (string, string, error) {
	subnet, gateway, _, err := backend.ResolveNetwork(be, opts.Subnet)
	if err != nil {
		if opts.Subnet != "" {
			return "", "", fmt.Errorf("invalid subnet: %w", err)
		}
		return "", "", fmt.Errorf("failed to allocate subnet: %w", err)
	}

	// An explicit --subnet bypasses the auto-allocator's route-aware skipping, so
	// warn (never fail -- it's a deliberate override) when the host already routes
	// the chosen subnet elsewhere (e.g. a VPN split-include), which would leave the
	// guest unreachable from the host. No-op under test (RouteConflicts defaults to
	// a no-op unless the binary wired the real prober).
	if opts.Subnet != "" && config.RouteConflicts(gateway) {
		cs := opts.Factory.ColorScheme
		errOut := opts.Factory.IO.ErrOut
		fmt.Fprintln(errOut, cs.Yellow(cs.Bold("WARNING:"))+cs.Yellow(fmt.Sprintf(" subnet %s appears already routed by the host (VPN?).", subnet)))
		fmt.Fprintln(errOut, cs.Yellow("host-to-guest traffic (SSH, mount) may be unreachable. Choose a different"))
		fmt.Fprintln(errOut, cs.Yellow("--subnet or disconnect the VPN."))
	}

	return subnet, gateway, nil
}

// buildInstanceConfig constructs the instance configuration struct.
func buildInstanceConfig(opts *Options, name string, paths *config.Paths, be backend.Backend, gateway, subnet string) *config.Instance {
	return &config.Instance{
		Version:    config.CurrentInstanceVersion,
		Name:       name,
		Backend:    be.Name(),
		StorageDir: be.StorageDir(),
		CPUs:       opts.CPUs,
		Memory:     opts.Memory,
		Base:       opts.Base,
		Subnet:     subnet,
		Gateway:    gateway,
		Bridge:     be.ResourceNames(name).Network,
		DNS: config.DNSConfig{
			Port:     0, // auto-allocated by dnsfilter
			Upstream: opts.Upstream,
		},
		HTTP: config.HTTPConfig{
			MITM:                opts.MITM,
			MaxConnections:      opts.MaxConnections,
			AllowPrivateTargets: opts.AllowPrivateTargets,
			AllowedPorts:        opts.AllowedPorts,
			SecretInjections:    opts.SecretInjections,
			MITMExceptions:      opts.MITMExceptions,
		},
		Monitor: config.MonitorConfig{
			Enabled:     opts.MonitorEnabled,
			Version:     opts.MonitorVersion,
			KprobeMulti: opts.MonitorKprobeMulti,
			Kprobes:     opts.MonitorKprobes,
			Policies:    opts.MonitorPolicies,
		},
		SSHKey:     paths.SSHKey,
		User:       opts.User,
		Disk:       opts.Disk,
		MACAddress: be.GenerateMAC(),
		IPAddress:  config.DeriveHostIP(gateway),
	}
}

// createInstanceResources creates SSH keys, CA cert, allowlist, network, disk, and VM.
// It updates cleanup state as resources are created for rollback on failure.
func createInstanceResources(
	ctx context.Context,
	opts *Options,
	cs *cleanupState,
	be backend.Backend,
	tv backend.TemplateValidator,
	templateSupported bool,
	paths *config.Paths,
	inst *config.Instance,
	w io.Writer,
) error {
	// Generate SSH key
	fmt.Fprintln(w, "  Generating SSH key...")
	if err := generateSSHKey(paths.SSHKey); err != nil {
		return fmt.Errorf("failed to generate SSH key: %w", err)
	}
	cs.sshKeyGen = true

	// Generate CA certificate for TLS MITM (only if MITM is enabled)
	if opts.MITM {
		fmt.Fprintln(w, "  Generating CA certificate...")
		if err := generateCACert(inst.Name, paths); err != nil {
			return fmt.Errorf("failed to generate CA certificate: %w", err)
		}
		cs.caKeyGen = true
	}

	// Note: cloud-init ISO generation is deferred to 'abox start' when the actual
	// DNS and HTTP filter ports are known. The domain XML template conditionally
	// includes the CDROM device only when the ISO exists.

	// Create allowlist (use boxfile allowlist if specified, otherwise defaults)
	fmt.Fprintln(w, "  Creating allowlist...")
	if err := createAllowlist(paths.Allowlist, opts.Allowlist); err != nil {
		return fmt.Errorf("failed to create allowlist: %w", err)
	}
	cs.allowlistGen = true

	// Create network
	fmt.Fprintln(w, "  Creating network...")
	if err := be.Network().Create(ctx, inst); err != nil {
		return fmt.Errorf("failed to create network: %w", err)
	}
	cs.networkDef = true

	if err := be.Network().Start(ctx, inst.Bridge); err != nil {
		return fmt.Errorf("failed to start network: %w", err)
	}
	cs.networkStart = true

	// Note: nwfilter is created during 'abox start' after dnsfilter allocates
	// its port, since the filter needs the actual DNS port.

	// Ensure base image is available for the backend
	fmt.Fprintln(w, "  Preparing base image...")
	if err := be.Disk().EnsureBaseImage(ctx, inst, paths); err != nil {
		return fmt.Errorf("failed to prepare base image: %w", err)
	}

	// Create disk from base image
	fmt.Fprintln(w, "  Creating disk image...")
	if err := be.Disk().Create(ctx, inst, paths); err != nil {
		return fmt.Errorf("failed to create disk: %w", err)
	}
	cs.diskCreated = true

	// Create VM
	fmt.Fprintln(w, "  Creating VM...")
	if opts.TemplateContent != "" && templateSupported {
		if err := tv.ValidateCustomTemplate(opts.TemplateContent); err != nil {
			return fmt.Errorf("custom domain template is invalid: %w", err)
		}
	}
	vmOpts := backend.VMCreateOptions{
		MonitorEnabled: inst.Monitor.Enabled,
		CustomTemplate: opts.TemplateContent,
	}
	if err := be.VM().Create(ctx, inst, paths, vmOpts); err != nil {
		return fmt.Errorf("failed to create VM: %w", err)
	}
	cs.domainDef = true

	// Note: iptables rules are set up during 'abox start' after the DNS filter
	// starts and allocates a port.
	return nil
}

// printCreateSummary prints the success message and audit log entry.
func printCreateSummary(opts *Options, name string, inst *config.Instance, subnet string, w io.Writer) {
	if !opts.Brief {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Instance %q created successfully!\n", name)
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Next steps:")
		fmt.Fprintf(w, "  abox start %s      # Start the VM\n", name)
		fmt.Fprintf(w, "  abox provision %s  # Run provision scripts\n", name)
		fmt.Fprintf(w, "  abox net filter %s active  # Verify filter is in active mode\n", name)
		fmt.Fprintf(w, "  abox ssh %s        # SSH into the VM\n", name)
	}

	logging.AuditInstance(name, logging.ActionInstanceCreate,
		"cpus", inst.CPUs,
		"memory", inst.Memory,
		"base", inst.Base,
		"subnet", subnet,
	)
}

func generateSSHKey(path string) error {
	// Remove existing key if present
	os.Remove(path)
	os.Remove(path + ".pub")

	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", path, "-N", "", "-C", "abox")
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return err
	}

	// Ensure restrictive permissions on private key
	// ssh-keygen usually does this, but verify to be safe regardless of system umask
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("failed to set SSH key permissions: %w", err)
	}

	return nil
}

func generateCACert(name string, paths *config.Paths) error {
	// Generate CA certificate for TLS MITM
	commonName := fmt.Sprintf("abox-%s CA", name)
	certPEM, keyPEM, err := cert.GenerateCA(commonName)
	if err != nil {
		return err
	}

	// Write certificate (readable by httpfilter and for cloud-init injection)
	if err := os.WriteFile(paths.CACert, certPEM, 0o644); err != nil { //nolint:gosec // CA cert must be readable by httpfilter and cloud-init
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	// Write private key (only readable by httpfilter process)
	if err := os.WriteFile(paths.CAKey, keyPEM, 0o600); err != nil {
		return fmt.Errorf("failed to write CA key: %w", err)
	}

	return nil
}

func createDefaultAllowlist(path string) error {
	content := `# Abox Domain Allowlist
# One domain per line. Subdomains are automatically allowed.
# Lines starting with # are comments.
#
# No domains are allowed by default. Add domains as needed:
#   abox allowlist add <instance> example.com
#   abox allowlist add <instance> "*.github.com"
#
# Or specify domains in abox.yaml:
#   allowlist:
#     - "*.github.com"
#     - "*.pypi.org"
`
	// Use restrictive permissions for allowlist file
	return os.WriteFile(path, []byte(content), 0o600)
}

// createAllowlist writes an allowlist file. If domains is nil, writes default domains.
// If domains is an empty slice, writes an empty allowlist (no defaults).
func createAllowlist(path string, domains []string) error {
	if domains == nil {
		// No allowlist specified in boxfile - use defaults
		return createDefaultAllowlist(path)
	}

	// Use boxfile allowlist (may be empty)
	return WriteAllowlist(path, domains)
}

// WriteAllowlist writes domains to an allowlist file.
// This is exported for use by the up command when syncing existing instances.
func WriteAllowlist(path string, domains []string) error {
	var sb strings.Builder
	sb.WriteString("# Domain Allowlist (from abox.yaml)\n")
	sb.WriteString("# One domain per line. Subdomains are automatically allowed.\n\n")
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain != "" {
			sb.WriteString(domain)
			sb.WriteString("\n")
		}
	}
	return os.WriteFile(path, []byte(sb.String()), 0o600)
}

// runDryRun generates and prints backend-specific config using example values
// without creating any resources.
func runDryRun(opts *Options, name string, paths *config.Paths, be backend.Backend) error {
	// Use example values for subnet/gateway since we don't want to allocate
	subnet := opts.Subnet
	var gateway string
	var err error
	if subnet == "" {
		subnet = "10.10.10.0/24"
		gateway = "10.10.10.1"
	} else {
		// Validate the provided subnet
		gateway, _, err = config.ValidateSubnet(opts.Subnet)
		if err != nil {
			return fmt.Errorf("invalid subnet: %w", err)
		}
	}

	// Validate custom template before generating dry-run output.
	// Boxfile.Validate() only checks syntax; this also validates field references.
	tv, templateSupported := be.(backend.TemplateValidator)
	if opts.TemplateContent != "" && templateSupported {
		if err := tv.ValidateCustomTemplate(opts.TemplateContent); err != nil {
			return fmt.Errorf("custom domain template is invalid: %w", err)
		}
	}

	// Create instance config with example values
	inst := &config.Instance{
		Version: config.CurrentInstanceVersion,
		Name:    name,
		Backend: be.Name(),
		CPUs:    opts.CPUs,
		Memory:  opts.Memory,
		Base:    opts.Base,
		Subnet:  subnet,
		Gateway: gateway,
		Bridge:  be.ResourceNames(name).Network,
		DNS: config.DNSConfig{
			Port:     5353, // example port
			Upstream: opts.Upstream,
		},
		HTTP: config.HTTPConfig{
			Port: 8080, // example port
		},
		SSHKey:     paths.SSHKey,
		User:       opts.User,
		Disk:       opts.Disk,
		MACAddress: be.GenerateMAC(),
		IPAddress:  config.DeriveHostIP(gateway),
	}
	if opts.TemplateContent != "" && templateSupported {
		tv.SetCustomTemplate(inst, true)
	}

	return be.DryRun(inst, paths, opts.Factory.IO.Out, backend.VMCreateOptions{
		CustomTemplate: opts.TemplateContent,
	})
}
