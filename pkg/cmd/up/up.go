package up

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/sandialabs/abox/internal/allowlist"
	"github.com/sandialabs/abox/internal/boxfile"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/dnsfilter"
	"github.com/sandialabs/abox/internal/httpfilter"
	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/reconcile"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/sshutil"
	"github.com/sandialabs/abox/internal/tui"
	"github.com/sandialabs/abox/pkg/cmd/create"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/provision"
	"github.com/sandialabs/abox/pkg/cmd/start"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// EnvConfPolicy is the environment-variable fallback for --conf-policy, used to
// resolve allowlist divergence non-interactively (CI). Mirrors ABOX_TRUST_BOXFILE.
const EnvConfPolicy = "ABOX_CONF_POLICY"

// Options holds the options for the up command.
type Options struct {
	Factory      *factory.Factory
	Dir          string
	Suffix       string
	TrustBoxfile string // expected abox.yaml fingerprint for non-interactive trust (--trust-boxfile / ABOX_TRUST_BOXFILE)
	ConfPolicy   string // how to reconcile a diverged allowlist.conf: keep|replace|prompt (--conf-policy / ABOX_CONF_POLICY)

	// confDecision is ConfPolicy parsed once in runUp; downstream reconcile uses
	// it directly rather than re-parsing the raw string.
	confDecision reconcile.Decision
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

For an existing instance, abox up reconciles the allowlist against abox.yaml
(see --conf-policy) and WARNS about any other abox.yaml field that differs from
the instance's saved config (cpus, memory, http/dns/monitor settings). Those
other fields are not re-applied to an existing instance; the warning shows how
to apply each one.

Use --suffix to run the same abox.yaml as several independent instances; the
suffix is appended to the name (e.g. name "my-agent" with --suffix 1 becomes
"my-agent-1").

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
		Example: `  abox up                                  # Instance from abox.yaml
  abox up --suffix 1                       # Same config as a separate instance "<name>-1"
  abox up --suffix 2                       # Another independent instance "<name>-2"`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if runF != nil {
				return runF(opts)
			}
			return runUp(cmd.Context(), opts)
		},
	}

	cmd.Flags().StringVarP(&opts.Dir, "dir", "d", "", "Directory containing abox.yaml (default: current directory)")
	cmd.Flags().StringVarP(&opts.Suffix, "suffix", "s", "", "Append a suffix to the instance name (run one abox.yaml as multiple instances)")
	cmd.Flags().StringVar(&opts.TrustBoxfile, "trust-boxfile", "", "Expected abox.yaml security fingerprint; trusts a security-relevant abox.yaml non-interactively (for CI). Source the value from a separately-reviewed channel, not the same checkout.")
	cmd.Flags().StringVar(&opts.ConfPolicy, "conf-policy", "", "When abox.yaml's allowlist differs from an existing instance's on-disk allowlist: keep (on-disk), replace (with abox.yaml), or prompt. Default: prompt interactively, keep non-interactively.")

	return cmd
}

func runUp(ctx context.Context, opts *Options) error {
	// Load abox.yaml (with its raw bytes for the trust fingerprint).
	box, boxDir, rawYAML, err := boxfile.LoadRaw(opts.Dir)
	if err != nil {
		return err
	}

	// Append the suffix so the same abox.yaml can back several instances.
	// Validation below checks the final (suffixed) name.
	box.ApplySuffix(opts.Suffix)

	// Validate configuration
	if err := box.Validate(boxDir); err != nil {
		return err
	}

	// Resolve the allowlist reconcile policy (flag, then env fallback) and
	// validate it up front so a bad value fails before any work happens.
	if opts.ConfPolicy == "" {
		opts.ConfPolicy = os.Getenv(EnvConfPolicy)
	}
	decision, err := reconcile.ParseDecision(opts.ConfPolicy)
	if err != nil {
		return fmt.Errorf("invalid --conf-policy: %w", err)
	}
	opts.confDecision = decision

	factory.Ensure(&opts.Factory)

	// Trust gate: confirm a security-relevant abox.yaml before acting on any
	// of its settings — and before the sudo/privilege pre-auth in runUpTUI.
	trustToken := opts.TrustBoxfile
	if trustToken == "" {
		trustToken = os.Getenv("ABOX_TRUST_BOXFILE")
	}
	if err := cmdutil.TrustBoxfile(opts.Factory.IO, opts.Factory.Prompter, opts.Factory.ColorScheme, box, rawYAML, boxDir, trustToken); err != nil {
		return err
	}

	// Resolve the allowlist reconcile decision NOW, before any TUI takes over the
	// terminal. Like the trust gate above, this may prompt interactively, and the
	// TUI path runs its work inside a bubbletea program that owns stdin/screen —
	// prompting from there would corrupt the display or hang. For an existing
	// instance we turn a possible DecisionPrompt into a concrete Keep/Replace here;
	// the in-TUI syncAllowlist then only applies the resolved decision.
	if config.Exists(box.Name) {
		resolveConfDecision(opts, box)
	}

	if opts.Factory.IO.IsTerminal() {
		return runUpTUI(ctx, opts, box, boxDir)
	}
	return runUpPlain(ctx, opts, box, boxDir)
}

// resolveConfDecision turns opts.confDecision into a concrete Keep/Replace for an
// existing instance's allowlist, prompting interactively if the policy is Prompt.
// It must run before any TUI starts (see runUp). Failures are non-fatal: the
// decision is left as-is and syncAllowlist falls back to its safe default (Keep).
func resolveConfDecision(opts *Options, box *boxfile.Boxfile) {
	if box.Allowlist == nil {
		return // nothing declared to reconcile
	}
	_, paths, err := opts.Factory.Config(box.Name)
	if err != nil {
		logging.Warn("failed to load instance config for allowlist reconcile", "error", err)
		return
	}

	req, err := buildReconcileRequest(opts, box, paths.Allowlist)
	if err != nil {
		logging.Warn("failed to read allowlist for reconcile", "error", err)
		return
	}

	decision, err := reconcile.Resolve(opts.Factory.IO, opts.Factory.Prompter, opts.Factory.ColorScheme, req)
	if err != nil {
		logging.Warn("failed to resolve allowlist reconcile decision", "error", err)
		return
	}
	opts.confDecision = decision
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
	// Both new and existing instances may need privileges (iptables egress rules).
	if _, err := opts.Factory.EgressClientFor(box.Name); err != nil {
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

// startRunFn is a test seam for the start phase. start.Run spawns the filter
// daemons as detached child processes (see startDaemonProcess in
// pkg/cmd/start/filter.go) whose socket/PID files live in $XDG_RUNTIME_DIR, not
// under the instance directory — so a unit test that reaches it escapes its
// temp-dir sandbox and leaves processes behind. Tests swap this for a no-op to
// exercise the create phase alone. Matches the startDNSFilterFn/applyFilteredFn
// seams in pkg/cmd/start, which exist for the same reason.
var startRunFn = start.Run

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

	// Phase 0: Create. Hand the parsed boxfile to create rather than mapping it
	// here: create owns the single abox.yaml -> Options mapping, and it resolves
	// monitor policies and overrides.<backend>.template itself (the latter needs
	// the backend, which it detects).
	notify.PhaseStart(0)
	if err := create.RunFromBoxfile(ctx, opts.Factory, box, boxDir, true); err != nil {
		notify.PhaseDone(0, err)
		return fmt.Errorf("failed to create instance: %w", err)
	}
	notify.PhaseDone(0, nil)

	// Phase 1: Start
	notify.PhaseStart(1)
	if err := startRunFn(ctx, &start.Options{Factory: opts.Factory, Brief: true}, box.Name); err != nil {
		notify.PhaseDone(1, err)
		return fmt.Errorf("failed to start instance: %w", err)
	}
	notify.PhaseDone(1, nil)

	// Phase 2: Secure
	notify.PhaseStart(2)
	be, err := opts.Factory.BackendFor(box.Name)
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

	// Apply the already-resolved allowlist decision (resolveConfDecision ran
	// pre-TUI) and warn about any other config drift. Failures here are non-fatal
	// — we still start the instance.
	if inst, paths, err := opts.Factory.Config(box.Name); err != nil {
		logging.Warn("failed to load instance config for reconcile", "error", err)
	} else {
		if box.Allowlist != nil {
			if err := syncAllowlist(opts, box, paths.Allowlist, w); err != nil {
				logging.Warn("failed to reconcile allowlist", "error", err)
			}
		}
		warnConfigDrift(opts, box, inst)
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
	if err := startRunFn(ctx, &start.Options{Factory: opts.Factory, Brief: true}, box.Name); err != nil {
		notify.PhaseDone(0, err)
		return fmt.Errorf("failed to start instance: %w", err)
	}

	notify.PhaseDone(0, nil)
	return nil
}

// buildReconcileRequest computes the reconcile inputs (normalized current vs
// desired domain sets, equality, and the rendered diff view) for the instance's
// allowlist. Shared by resolveConfDecision (which prompts, pre-TUI) and
// syncAllowlist (which applies) so the two agree on exactly what "diverged" means.
func buildReconcileRequest(opts *Options, box *boxfile.Boxfile, allowlistPath string) (reconcile.Request, error) {
	desired := allowlist.DomainSet(box.Allowlist)
	current, err := allowlist.LoadDomainSet(allowlistPath)
	if err != nil {
		return reconcile.Request{}, err
	}
	return reconcile.Request{
		Subject:  fmt.Sprintf("the allowlist for instance %q", box.Name),
		Equal:    allowlist.DomainSetsEqual(current, desired),
		Current:  allowlist.RenderDomainSet(current),
		Desired:  allowlist.RenderDomainSet(desired),
		Decision: opts.confDecision,
	}, nil
}

// syncAllowlist applies the already-resolved reconcile decision
// (opts.confDecision, set by resolveConfDecision before any TUI started) to the
// on-disk allowlist. It never prompts — it runs inside the bubbletea work
// goroutine on the TUI path, where prompting would corrupt the display. Only
// DecisionReplace overwrites the file; anything else keeps the on-disk version,
// so a manual `abox allowlist add/remove` is not clobbered on `abox up`.
func syncAllowlist(opts *Options, box *boxfile.Boxfile, allowlistPath string, w io.Writer) error {
	req, err := buildReconcileRequest(opts, box, allowlistPath)
	if err != nil {
		return err
	}

	if opts.confDecision == reconcile.DecisionReplace {
		if err := create.WriteAllowlist(allowlistPath, box.Allowlist); err != nil {
			return err
		}
		fmt.Fprintln(w, "Synced allowlist from abox.yaml")
		return nil
	}

	// Everything else keeps the on-disk allowlist.
	if opts.confDecision == reconcile.DecisionPrompt {
		// DecisionPrompt should have been resolved to Keep/Replace by
		// resolveConfDecision before the TUI. If it wasn't (that step was skipped
		// or failed), fail safe to Keep rather than prompt from here — surface it
		// so the gap is visible instead of silent.
		logging.Warn("allowlist reconcile decision unresolved; keeping on-disk allowlist", "instance", box.Name)
	}
	// Only comment when the sets actually differed (the common equal case stays quiet).
	if !req.Equal {
		fmt.Fprintln(w, "Kept the existing allowlist; abox.yaml differs (pass --conf-policy=replace to sync).")
	}
	return nil
}

// warnConfigDrift prints a warning for each abox.yaml field that differs from
// the existing instance's saved config. `abox up` does not re-apply these to an
// existing instance, so the warning surfaces what would otherwise be a silent
// no-op and tells the user how to apply each field.
func warnConfigDrift(opts *Options, box *boxfile.Boxfile, inst *config.Instance) {
	diffs := boxfile.Drift(box, inst)
	if len(diffs) == 0 {
		return
	}

	cs := opts.Factory.ColorScheme
	errOut := opts.Factory.IO.ErrOut
	fmt.Fprintln(errOut)
	fmt.Fprintln(errOut, cs.Yellow(cs.Bold("WARNING:"))+cs.Yellow(fmt.Sprintf(" abox.yaml differs from instance %q; abox up does not apply these to an existing instance:", box.Name)))
	for _, d := range diffs {
		fmt.Fprintln(errOut, cs.Yellow("  - "+d.String()))
	}
	fmt.Fprintln(errOut)
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
