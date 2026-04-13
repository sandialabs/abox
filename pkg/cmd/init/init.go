package init

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/sandialabs/abox/internal/boxfile"
	"github.com/sandialabs/abox/internal/validation"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

// Options holds the options for the init command.
type Options struct {
	Factory       *factory.Factory
	Defaults      bool
	Stdout        bool
	Force         bool
	Output        string
	DryRun        bool
	outputChanged bool // set by RunE when --output is explicitly passed
}

// initResult holds the output of promptForConfig: the boxfile and selected features.
type initResult struct {
	box      *boxfile.Boxfile
	selected []int // indices into features slice
}

// NewCmdInit creates a new init command.
func NewCmdInit(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
		Output:  "abox.yaml",
	}

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate an abox.yaml configuration file",
		Long: `Generate an abox.yaml configuration file.

By default, prompts interactively for each field with defaults shown in brackets.
Press Enter to accept the default value.

Use --defaults to skip prompts and output a configuration with all default values.
Use --stdout to write to stdout instead of a file (useful for piping or previewing).

Example:
  abox init                    # Interactive mode, creates abox.yaml
  abox init --defaults         # Non-interactive with defaults
  abox init --stdout           # Preview to stdout
  abox init --output myconfig.yaml   # Custom output path`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.outputChanged = cmd.Flags().Changed("output")
			if runF != nil {
				return runF(opts)
			}
			return runInit(opts)
		},
	}

	cmd.Flags().BoolVar(&opts.Defaults, "defaults", false, "Skip prompts and use all default values")
	cmd.Flags().BoolVar(&opts.Stdout, "stdout", false, "Write to stdout instead of file")
	cmd.Flags().BoolVarP(&opts.Force, "force", "f", false, "Overwrite existing abox.yaml")
	cmd.Flags().StringVar(&opts.Output, "output", "abox.yaml", "Output file path")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Preview output without writing (alias for --stdout)")

	return cmd
}

func runInit(opts *Options) error {
	if opts.DryRun {
		opts.Stdout = true
	}

	if err := cmdutil.MutuallyExclusive(
		[]string{"--stdout", "--output"},
		[]bool{opts.Stdout, opts.outputChanged},
	); err != nil {
		return err
	}

	var result initResult

	if opts.Defaults {
		result.box = boxfile.DefaultBoxfile()
	} else {
		result = promptForConfig(opts.Factory)
	}

	// Generate YAML output
	output, err := generateYAML(result.box)
	if err != nil {
		return fmt.Errorf("failed to generate YAML: %w", err)
	}

	if opts.Stdout {
		fmt.Fprint(opts.Factory.IO.Out, output)
		return nil
	}

	// Check if file exists
	if !opts.Force {
		if _, err := os.Stat(opts.Output); err == nil {
			return cmdutil.FlagErrorf("%s already exists (use --force to overwrite)", opts.Output)
		}
	}

	// Write abox.yaml
	if err := os.WriteFile(opts.Output, []byte(output), 0o644); err != nil { //nolint:gosec // config file, not sensitive
		return fmt.Errorf("failed to write %s: %w", opts.Output, err)
	}

	errOut := opts.Factory.IO.ErrOut
	fmt.Fprintf(errOut, "Created %s\n", opts.Output)

	// Write feature scripts and overlay files
	if len(result.selected) > 0 {
		if err := writeFeatureFiles(result.selected, errOut); err != nil {
			return err
		}
	}

	// Print domain hints
	printDomainHints(result.box.Name, result.selected, errOut)

	fmt.Fprintln(errOut)
	fmt.Fprintln(errOut, "Next steps:")
	fmt.Fprintln(errOut, "  1. Review and customize the configuration")
	fmt.Fprintln(errOut, "  2. Run 'abox up' to create and start the instance")

	return nil
}

func promptForConfig(f *factory.Factory) initResult {
	p := f.Prompter
	defaults := boxfile.DefaultBoxfile()
	box := &boxfile.Boxfile{
		Version: boxfile.CurrentBoxfileVersion,
	}

	box.Name = promptName(f, p)
	box.CPUs = promptCPUs(f, p, defaults.CPUs)
	box.Memory = promptMemory(f, p, defaults.Memory)
	box.Disk = promptDisk(f, p, defaults.Disk)
	box.Base = p.Input("Base image", defaults.Base)
	box.User = p.Input("SSH username", defaults.User)
	box.DNS.Upstream = promptUpstreamDNS(f, p, defaults.DNS.Upstream)
	box.Monitor.Enabled, box.Monitor.Version = promptMonitor(p)

	mitm := p.ConfirmWithDefault("Enable TLS MITM for HTTP proxy? [Y/n] ", true)
	box.HTTP.MITM = &mitm

	selected := promptFeatures(p)
	if len(selected) > 0 {
		box.Provision, box.Overlay = buildBoxfileEntries(selected)
	}

	return initResult{box: box, selected: selected}
}

// promptName prompts for and validates an instance name.
func promptName(f *factory.Factory, p cmdutil.Prompter) string {
	for {
		name := p.Input("Instance name", "")
		if name == "" {
			fmt.Fprintln(f.IO.ErrOut, "  Instance name is required")
			continue
		}
		if err := validation.ValidateInstanceName(name); err != nil {
			fmt.Fprintf(f.IO.ErrOut, "  %v\n", err)
			continue
		}
		return name
	}
}

// promptCPUs prompts for and validates the CPU count.
func promptCPUs(f *factory.Factory, p cmdutil.Prompter, defaultCPUs int) int {
	for {
		input := p.Input("Number of CPUs", strconv.Itoa(defaultCPUs))
		val, err := strconv.Atoi(input)
		if err != nil {
			fmt.Fprintln(f.IO.ErrOut, "  Please enter a valid number")
			continue
		}
		if val < validation.MinCPUs || val > validation.MaxCPUs {
			fmt.Fprintf(f.IO.ErrOut, "  CPUs must be between %d and %d\n", validation.MinCPUs, validation.MaxCPUs)
			continue
		}
		return val
	}
}

// promptMemory prompts for and validates the memory size.
func promptMemory(f *factory.Factory, p cmdutil.Prompter, defaultMemory int) int {
	for {
		input := p.Input("Memory in MB", strconv.Itoa(defaultMemory))
		val, err := strconv.Atoi(input)
		if err != nil {
			fmt.Fprintln(f.IO.ErrOut, "  Please enter a valid number")
			continue
		}
		if val < validation.MinMemory || val > validation.MaxMemory {
			fmt.Fprintf(f.IO.ErrOut, "  memory must be between %d and %d MB\n", validation.MinMemory, validation.MaxMemory)
			continue
		}
		return val
	}
}

// promptDisk prompts for and validates the disk size.
func promptDisk(f *factory.Factory, p cmdutil.Prompter, defaultDisk string) string {
	for {
		input := p.Input("Disk size", defaultDisk)
		if err := validation.ValidateDiskSize(strings.ToUpper(input)); err != nil {
			fmt.Fprintf(f.IO.ErrOut, "  %v\n", err)
			continue
		}
		return strings.ToUpper(input)
	}
}

// promptUpstreamDNS prompts for and validates the upstream DNS server.
func promptUpstreamDNS(f *factory.Factory, p cmdutil.Prompter, defaultUpstream string) string {
	for {
		upstream := p.Input("Upstream DNS server", defaultUpstream)
		normalized, err := validation.NormalizeUpstreamDNS(upstream)
		if err != nil {
			fmt.Fprintf(f.IO.ErrOut, "  %v\n", err)
			continue
		}
		return normalized
	}
}

// promptMonitor prompts for monitor settings and returns (enabled, version).
func promptMonitor(p cmdutil.Prompter) (bool, string) {
	enabled := p.ConfirmWithDefault("Enable Tetragon monitoring? [y/N] ", false)
	if !enabled {
		return false, ""
	}
	version := p.Input("Tetragon version (empty for latest)", "")
	return true, version
}

// promptFeatures displays the feature picker using the Prompter abstraction
// and returns selected 0-based indices into the features slice.
func promptFeatures(p cmdutil.Prompter) []int {
	opts := make([]cmdutil.Option, len(features))
	for i, f := range features {
		opts[i] = cmdutil.Option{Label: f.Name, Description: f.Desc}
	}
	return p.MultiSelect("Features to install:", opts)
}

// buildBoxfileEntries returns the provision script list and overlay directory
// to include in the generated abox.yaml based on selected features.
func buildBoxfileEntries(selected []int) (provision []string, overlay string) {
	// Always include abox-setup
	provision = append(provision, "scripts/00-abox-setup.sh")

	// Check if overlay is needed
	needsOverlay := false
	for _, idx := range selected {
		if len(features[idx].Overlay) > 0 {
			needsOverlay = true
			break
		}
	}

	if needsOverlay {
		provision = append(provision, "scripts/10-apply-overlay.sh")
		overlay = "overlay"
	}

	// Add feature scripts with gaps of 10
	scriptNum := 20
	for _, idx := range selected {
		for _, script := range features[idx].Scripts {
			provision = append(provision, fmt.Sprintf("scripts/%02d-%s", scriptNum, script))
			scriptNum += 10
		}
	}

	// Sort provision scripts to ensure consistent ordering
	sort.Strings(provision)

	return provision, overlay
}

func generateYAML(box *boxfile.Boxfile) (string, error) {
	var sb strings.Builder
	sb.WriteString("# abox instance configuration\n")
	sb.WriteString("# See 'abox yaml' for full reference\n\n")

	data, err := yaml.Marshal(box)
	if err != nil {
		return "", err
	}

	sb.Write(data)
	return sb.String(), nil
}

// writeFeatureFiles writes provision scripts and overlay files for selected features.
func writeFeatureFiles(selected []int, out io.Writer) error {
	// Always write the abox-setup script first
	scriptNum := 0
	if err := writeScript(scriptNum, "abox-setup.sh", out); err != nil {
		return err
	}

	// Check if any selected feature needs an overlay
	needsOverlay := false
	for _, idx := range selected {
		if len(features[idx].Overlay) > 0 {
			needsOverlay = true
			break
		}
	}

	if needsOverlay {
		scriptNum += 10
		if err := writeScript(scriptNum, "apply-overlay.sh", out); err != nil {
			return err
		}
	}

	// Write feature scripts
	scriptNum = 20
	for _, idx := range selected {
		f := features[idx]
		for _, script := range f.Scripts {
			if err := writeScript(scriptNum, script, out); err != nil {
				return err
			}
			scriptNum += 10
		}

		// Write overlay files
		for overlayPath, tmplName := range f.Overlay {
			if err := writeOverlayFile(overlayPath, tmplName, out); err != nil {
				return err
			}
		}
	}

	return nil
}

// writeScript reads a template and writes it as a numbered script in scripts/.
func writeScript(num int, templateName string, out io.Writer) error {
	content, err := templateFS.ReadFile("templates/" + templateName)
	if err != nil {
		return fmt.Errorf("failed to read template %s: %w", templateName, err)
	}

	dir := "scripts"
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // project scripts dir needs 0o755
		return fmt.Errorf("failed to create scripts directory: %w", err)
	}

	filename := fmt.Sprintf("%02d-%s", num, templateName)
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, content, 0o755); err != nil { //nolint:gosec // provision scripts need exec permission
		return fmt.Errorf("failed to write %s: %w", path, err)
	}

	fmt.Fprintf(out, "Created %s\n", path)
	return nil
}

// writeOverlayFile reads a template and writes it into the overlay directory.
func writeOverlayFile(overlayPath, templateName string, out io.Writer) error {
	content, err := templateFS.ReadFile("templates/" + templateName)
	if err != nil {
		return fmt.Errorf("failed to read template %s: %w", templateName, err)
	}

	path := filepath.Join("overlay", overlayPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // overlay dir needs 0o755
		return fmt.Errorf("failed to create overlay directory: %w", err)
	}

	if err := os.WriteFile(path, content, 0o644); err != nil { //nolint:gosec // overlay config file, not sensitive
		return fmt.Errorf("failed to write %s: %w", path, err)
	}

	fmt.Fprintf(out, "Created %s\n", path)
	return nil
}

// printDomainHints prints suggested allowlist commands for selected features.
func printDomainHints(instanceName string, selected []int, out io.Writer) {
	var domains []string
	for _, idx := range selected {
		domains = append(domains, features[idx].Domains...)
	}

	if len(domains) == 0 {
		return
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Tip: You may want to allowlist these domains:")
	for _, d := range domains {
		if strings.ContainsAny(d, "*?") {
			fmt.Fprintf(out, "  abox allowlist add %s '%s'\n", instanceName, d)
		} else {
			fmt.Fprintf(out, "  abox allowlist add %s %s\n", instanceName, d)
		}
	}
}
