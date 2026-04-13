package up

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/sandialabs/abox/internal/boxfile"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/dnsfilter"
	"github.com/sandialabs/abox/internal/httpfilter"
	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/sshutil"
	"github.com/sandialabs/abox/internal/tui"
	"github.com/sandialabs/abox/pkg/cmd/create"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/provision"
	"github.com/sandialabs/abox/pkg/cmd/start"

	"github.com/spf13/cobra"
)

// Options holds the options for the up command.
type Options struct {
	Factory *factory.Factory
	Dir     string
}

// NewCmdUp creates a new up command.
func NewCmdUp(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "up",
		Short: "Create, start, and provision an instance from abox.yaml",
		Long: `Create, start, and provision an instance from abox.yaml.

This command reads abox.yaml from the current directory (or specified directory)
and:
  - Creates a new instance if it doesn't exist
  - Starts the instance if not running
  - Runs provision scripts (first time only)
  - Applies DNS allowlist
  - Applies filtered security restrictions (proxy only)

Subsequent runs are idempotent - they will just ensure the instance is running.

Example abox.yaml:
  name: my-agent
  cpus: 4
  memory: 8192
  base: ubuntu-24.04
  provision:
    - provision.sh
  allowlist:
    - "*.github.com"
    - "*.anthropic.com"`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if runF != nil {
				return runF(opts)
			}
			return runUp(cmd.Context(), opts)
		},
	}

	cmd.Flags().StringVarP(&opts.Dir, "dir", "d", "", "Directory containing abox.yaml (default: current directory)")

	return cmd
}

func runUp(ctx context.Context, opts *Options) error {
	// Load abox.yaml
	box, boxDir, err := boxfile.Load(opts.Dir)
	if err != nil {
		return err
	}

	// Validate configuration
	if err := box.Validate(boxDir); err != nil {
		return err
	}

	factory.Ensure(&opts.Factory)

	if opts.Factory.IO.IsTerminal() {
		return runUpTUI(ctx, opts, box, boxDir)
	}
	return runUpPlain(ctx, opts, box, boxDir)
}

// ---------------------------------------------------------------------------
// Plain text path (non-TTY or pipe)
// ---------------------------------------------------------------------------

func runUpPlain(ctx context.Context, opts *Options, box *boxfile.Boxfile, boxDir string) error {
	w := opts.Factory.IO.Out
	fmt.Fprintf(w, "Using abox.yaml from %s\n", boxDir)
	fmt.Fprintf(w, "Instance: %s\n\n", box.Name)

	// Check if instance already exists
	if config.Exists(box.Name) {
		return doExistingInstance(ctx, opts, box, tui.NoopNotifier{})
	}

	if err := doNewInstance(ctx, opts, box, boxDir, tui.NoopNotifier{}); err != nil {
		return err
	}

	fmt.Fprintf(w, "\nInstance %q is ready!\n", box.Name)
	fmt.Fprintf(w, "\nSSH: abox ssh %s\n", box.Name)
	return nil
}

// ---------------------------------------------------------------------------
// TUI path
// ---------------------------------------------------------------------------

func runUpTUI(ctx context.Context, opts *Options, box *boxfile.Boxfile, boxDir string) error {
	isNew := !config.Exists(box.Name)

	// Pre-authenticate sudo before TUI takes over the terminal.
	// Both new and existing instances may need privileges (iptables, UFW, etc.).
	if _, err := opts.Factory.PrivilegeClientFor(box.Name); err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	// Build step list
	var steps []tui.Step

	if isNew {
		var err error
		steps, err = buildNewInstanceSteps(box, boxDir)
		if err != nil {
			return err
		}
	} else {
		steps = append(steps, tui.Step{Name: "Start instance"})
	}

	done := tui.DoneConfig{
		SuccessMsg: fmt.Sprintf("Instance %q is ready!", box.Name),
		HintLines:  []string{"SSH: abox ssh " + box.Name},
	}

	return tui.Run("abox up: "+box.Name, steps, done, func(out io.Writer, errOut io.Writer, notify tui.PhaseNotifier) error {
		f := opts.Factory
		f.IO.SetOutputSplit(out, errOut)
		defer f.IO.RestoreOutput()
		old := logging.StderrWriter().Swap(errOut)
		defer logging.StderrWriter().Swap(old)
		if isNew {
			return doNewInstance(ctx, opts, box, boxDir, notify)
		}
		return doExistingInstance(ctx, opts, box, notify)
	})
}

// ---------------------------------------------------------------------------
// Unified work functions (called by both TUI and plain paths)
// ---------------------------------------------------------------------------

// doNewInstance runs the full create+start+secure+provision pipeline.
func buildNewInstanceSteps(box *boxfile.Boxfile, boxDir string) ([]tui.Step, error) {
	steps := []tui.Step{
		{Name: "Create instance"},
		{Name: "Start filters and VM"},
		{Name: "Apply security restrictions"},
	}
	if len(box.Provision) > 0 {
		scripts, err := box.ResolveProvisionPaths(boxDir)
		if err != nil {
			return nil, err
		}
		if len(scripts) == 1 {
			steps = append(steps, tui.Step{Name: "Provision", Detail: filepath.Base(scripts[0])})
		} else {
			steps = append(steps, tui.Step{Name: "Provision"})
			for _, s := range scripts {
				steps = append(steps, tui.Step{Name: filepath.Base(s), Indent: 1})
			}
		}
	}
	return steps, nil
}

func doNewInstance(ctx context.Context, opts *Options, box *boxfile.Boxfile, boxDir string, notify tui.PhaseNotifier) error {
	w := opts.Factory.IO.Out

	// Phase 0: Create
	notify.PhaseStart(0)
	var monitorPolicies []string
	if len(box.Monitor.Policies) > 0 {
		var err error
		monitorPolicies, err = box.ResolvePolicyPaths(boxDir)
		if err != nil {
			notify.PhaseDone(0, err)
			return err
		}
	}
	// Detect backend to load the correct overrides (avoids hardcoding a backend name).
	be, err := opts.Factory.AutoDetectBackend()
	if err != nil {
		notify.PhaseDone(0, err)
		return fmt.Errorf("failed to detect backend: %w", err)
	}
	templateContent, err := box.LoadOverrideContent(be.Name(), "template", boxDir)
	if err != nil {
		notify.PhaseDone(0, err)
		return err
	}

	createOpts := &create.Options{
		Factory:         opts.Factory,
		CPUs:            box.CPUs,
		Memory:          box.Memory,
		Base:            box.Base,
		Upstream:        box.DNS.Upstream,
		Disk:            box.Disk,
		Subnet:          box.Subnet,
		User:            box.User,
		Allowlist:       box.Allowlist,
		MonitorEnabled:  box.Monitor.Enabled,
		MonitorVersion:  box.Monitor.Version,
		MonitorKprobes:  box.Monitor.Kprobes,
		MonitorPolicies: monitorPolicies,
		MITM:            box.GetMITM(),
		TemplateContent: templateContent,
		Brief:           true,
	}
	if err := create.Run(ctx, createOpts, box.Name); err != nil {
		notify.PhaseDone(0, err)
		return fmt.Errorf("failed to create instance: %w", err)
	}
	notify.PhaseDone(0, nil)

	// Phase 1: Start
	notify.PhaseStart(1)
	if err := start.Run(ctx, &start.Options{Factory: opts.Factory, Brief: true}, box.Name); err != nil {
		notify.PhaseDone(1, err)
		return fmt.Errorf("failed to start instance: %w", err)
	}
	notify.PhaseDone(1, nil)

	// Phase 2: Secure
	notify.PhaseStart(2)
	be, err = opts.Factory.BackendFor(box.Name)
	if err != nil {
		notify.PhaseDone(2, err)
		return fmt.Errorf("failed to get backend: %w", err)
	}
	if err := instance.ApplyFiltered(w, box.Name, be, true); err != nil {
		notify.PhaseDone(2, err)
		return fmt.Errorf("failed to apply network filter: %w", err)
	}
	notify.PhaseDone(2, nil)

	// Phase 3+: Provision (if scripts exist)
	if len(box.Provision) > 0 {
		provisionScripts, err := box.ResolveProvisionPaths(boxDir)
		if err != nil {
			return fmt.Errorf("failed to resolve provision scripts: %w", err)
		}
		// provisionIdx follows the 3 phases above (create=0, start=1, secure=2)
		const provisionIdx = 3
		if err := doProvision(ctx, opts, box, boxDir, provisionScripts, provisionIdx, notify); err != nil {
			return err
		}
	}

	logging.AuditInstance(box.Name, logging.ActionUp, "boxfile", boxDir)
	return nil
}

// doExistingInstance starts an existing instance.
func doExistingInstance(ctx context.Context, opts *Options, box *boxfile.Boxfile, notify tui.PhaseNotifier) error {
	w := opts.Factory.IO.Out
	notify.PhaseStart(0)

	// Sync allowlist if needed
	if box.Allowlist != nil {
		_, paths, err := config.Load(box.Name)
		if err != nil {
			logging.Warn("failed to load instance config for allowlist sync", "error", err)
		} else if err := create.WriteAllowlist(paths.Allowlist, box.Allowlist); err != nil {
			logging.Warn("failed to sync allowlist", "error", err)
		} else {
			fmt.Fprintln(w, "Synced allowlist from abox.yaml")
		}
	}

	be, err := opts.Factory.BackendFor(box.Name)
	if err != nil {
		notify.PhaseDone(0, err)
		return fmt.Errorf("failed to get backend: %w", err)
	}

	if be.VM().IsRunning(box.Name) {
		fmt.Fprintf(w, "Instance %q is already running\n", box.Name)
		notify.PhaseDone(0, nil)
		return nil
	}

	fmt.Fprintf(w, "Starting existing instance %q...\n", box.Name)
	if err := start.Run(ctx, &start.Options{Factory: opts.Factory, Brief: true}, box.Name); err != nil {
		notify.PhaseDone(0, err)
		return fmt.Errorf("failed to start instance: %w", err)
	}

	notify.PhaseDone(0, nil)
	return nil
}

// doProvision runs the provisioning phase: sets passive mode, waits for SSH,
// runs scripts, then sets active mode.
func doProvision(ctx context.Context, opts *Options, box *boxfile.Boxfile, boxDir string, scripts []string, provisionIdx int, notify tui.PhaseNotifier) error {
	w := opts.Factory.IO.Out

	// Set DNS and HTTP to passive mode during provisioning
	setFilterMode(opts.Factory, box.Name, "passive", w)

	// Restore active mode when done, regardless of how we exit
	defer func() {
		setFilterMode(opts.Factory, box.Name, "active", w)
	}()

	// Signal that provisioning has started so the TUI shows progress
	notify.PhaseStart(provisionIdx)

	// Wait for SSH
	fmt.Fprintln(w, "Waiting for SSH to be ready...")
	inst, paths, err := instance.LoadRequired(box.Name)
	if err != nil {
		err = fmt.Errorf("failed to load instance: %w", err)
		notify.PhaseDone(provisionIdx, err)
		return err
	}
	be, err := opts.Factory.BackendFor(box.Name)
	if err != nil {
		err = fmt.Errorf("failed to get backend: %w", err)
		notify.PhaseDone(provisionIdx, err)
		return err
	}
	ip, err := be.VM().GetIP(box.Name)
	if err != nil {
		err = fmt.Errorf("failed to get instance IP: %w", err)
		notify.PhaseDone(provisionIdx, err)
		return err
	}
	if err := sshutil.WaitForSSH(paths, inst.GetUser(), ip, 2*time.Minute); err != nil {
		err = fmt.Errorf("SSH not ready: %w", err)
		notify.PhaseDone(provisionIdx, err)
		return err
	}
	fmt.Fprintln(w, "SSH ready")

	// Wait for cloud-init
	fmt.Fprintln(w, "Waiting for cloud-init to complete...")
	if err := waitForCloudInit(ctx, paths, inst.GetUser(), ip); err != nil {
		logging.Warn("cloud-init completion check failed", "error", err, "instance", box.Name)
	} else {
		fmt.Fprintln(w, "Cloud-init done")
	}

	// Run provision scripts (single call — one overlay mount/unmount cycle)
	provisionOpts := &provision.Options{
		Factory: opts.Factory,
		Scripts: scripts,
		Overlay: resolveOverlayOrEmpty(box, boxDir),
		Brief:   true,
	}
	if len(scripts) > 1 {
		provisionOpts.OnScriptStart = func(i int) {
			notify.SubPhaseStart(provisionIdx, provisionIdx+1+i)
		}
		provisionOpts.OnScriptDone = func(i int, err error) {
			notify.SubPhaseDone(provisionIdx, provisionIdx+1+i, err)
		}
	}
	if err := provision.Run(ctx, provisionOpts, box.Name); err != nil {
		notify.PhaseDone(provisionIdx, err)
		return fmt.Errorf("failed to provision: %w", err)
	}
	notify.PhaseDone(provisionIdx, nil)

	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// resolveOverlayOrEmpty resolves the overlay path, returning empty string on error.
// Overlay path traversal is validated during create, so errors here are logged but non-fatal.
func resolveOverlayOrEmpty(box *boxfile.Boxfile, boxDir string) string {
	p, err := box.ResolveOverlayPath(boxDir)
	if err != nil {
		logging.Warn("failed to resolve overlay path", "error", err)
		return ""
	}
	return p
}

// setFilterMode sets both DNS and HTTP filter modes, logging warnings on failure.
func setFilterMode(f *factory.Factory, name string, mode string, w io.Writer) {
	if err := setDNSMode(f, name, mode); err != nil {
		logging.Warn("failed to set DNS mode", "error", err, "instance", name)
	} else {
		fmt.Fprintf(w, "DNS set to %s mode\n", mode)
	}

	if err := setHTTPMode(f, name, mode); err != nil {
		logging.Warn("failed to set HTTP mode", "error", err, "instance", name)
	} else {
		fmt.Fprintf(w, "HTTP set to %s mode\n", mode)
	}
}

func setDNSMode(f *factory.Factory, name, mode string) error {
	client, err := f.DNSClient(name)
	if err != nil {
		return err
	}
	ctx, cancel := dnsfilter.ClientContext()
	defer cancel()
	_, err = client.SetMode(ctx, &rpc.ModeReq{Mode: mode})
	return err
}

func setHTTPMode(f *factory.Factory, name, mode string) error {
	client, err := f.HTTPClient(name)
	if err != nil {
		return err
	}
	ctx, cancel := httpfilter.ClientContext()
	defer cancel()
	_, err = client.SetMode(ctx, &rpc.ModeReq{Mode: mode})
	return err
}

// waitForCloudInit waits for cloud-init to complete.
func waitForCloudInit(ctx context.Context, paths *config.Paths, user, ip string) error {
	args := sshutil.BuildSSHArgs(paths, user, ip, "cloud-init", "status", "--wait")

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ssh", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return errors.New("timed out waiting for cloud-init")
		}
		return fmt.Errorf("cloud-init status failed: %s", string(output))
	}
	return nil
}
