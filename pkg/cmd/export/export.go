package export

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/tui"
	"github.com/sandialabs/abox/internal/version"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// Manifest represents the archive manifest.json structure.
type Manifest struct {
	Version     int              `json:"version"`
	Format      string           `json:"format"`
	CreatedAt   string           `json:"created_at"`
	AboxVersion string           `json:"abox_version"`
	Snapshot    bool             `json:"snapshot"`
	Instance    ManifestInstance `json:"instance"`
}

// ManifestInstance contains instance metadata in the manifest.
type ManifestInstance struct {
	Name   string `json:"name"`
	CPUs   int    `json:"cpus"`
	Memory int    `json:"memory"`
	Base   string `json:"base"`
	Disk   string `json:"disk"`
}

// Options holds the options for the export command.
type Options struct {
	Factory    *factory.Factory
	Snapshot   bool
	Force      bool
	Name       string // Instance name (positional arg)
	OutputPath string // Optional output path (positional arg)
}

// NewCmdExport creates a new export command.
func NewCmdExport(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "export <instance> [output-path]",
		Short: "Export an abox instance to an archive",
		Long: `Export an abox instance to a portable .abox.tar.gz archive.

By default, the disk is flattened (merged with base image) for full portability.
Use --snapshot to export only the CoW delta (smaller, but requires the same base
image on the target machine).

The archive includes:
  - Instance configuration
  - Disk image (flattened or CoW delta)
  - SSH keys
  - DNS allowlist`,
		Example: `  abox export dev                          # Export to dev.abox.tar.gz
  abox export dev ~/backups/dev.tar.gz     # Custom output path
  abox export dev -s                       # Snapshot mode (smaller, requires same base)`,
		Args:              cobra.RangeArgs(1, 2),
		ValidArgsFunction: completion.Sequence(completion.AllInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if len(args) > 1 {
				opts.OutputPath = args[1]
			}
			if runF != nil {
				return runF(opts)
			}
			return runExport(cmd.Context(), opts, opts.Name, opts.OutputPath)
		},
	}

	cmd.Flags().BoolVarP(&opts.Snapshot, "snapshot", "s", false, "Export CoW delta only (smaller, requires same base image on target)")
	cmd.Flags().BoolVarP(&opts.Force, "force", "f", false, "Overwrite existing archive")

	return cmd
}

func runExport(ctx context.Context, opts *Options, name, outputPath string) error {
	// Load instance configuration
	inst, paths, err := instance.LoadRequired(name)
	if err != nil {
		return err
	}

	// Get the backend for this instance
	factory.Ensure(&opts.Factory)
	be, err := opts.Factory.BackendFor(name)
	if err != nil {
		return fmt.Errorf("failed to get backend: %w", err)
	}

	// Check VM is stopped
	if be.VM().IsRunning(name) {
		return &cmdutil.ErrHint{
			Err:  fmt.Errorf("instance %q is running", name),
			Hint: "Stop it first: abox stop " + name,
		}
	}

	// Determine output path
	if outputPath == "" {
		outputPath = name + ".abox.tar.gz"
	}

	// Check if output already exists
	if _, err := os.Stat(outputPath); err == nil && !opts.Force {
		return &cmdutil.ErrHint{
			Err:  fmt.Errorf("output file %q already exists", outputPath),
			Hint: "Use --force to overwrite",
		}
	}

	// Get privilege client for backend disk operations
	client, err := opts.Factory.PrivilegeClientFor(name)
	if err != nil {
		return fmt.Errorf("failed to get privilege client: %w", err)
	}

	if opts.Factory.IO.IsTerminal() {
		return runExportTUI(ctx, opts, name, outputPath, inst, paths, be, client)
	}
	return runExportPlain(ctx, opts, name, outputPath, inst, paths, be, client)
}

// ---------------------------------------------------------------------------
// Plain text path (non-TTY or pipe)
// ---------------------------------------------------------------------------

func runExportPlain(ctx context.Context, opts *Options, name, outputPath string, inst *config.Instance, paths *config.Paths, be backend.Backend, client rpc.PrivilegeClient) error {
	w := opts.Factory.IO.Out
	fmt.Fprintf(w, "Exporting instance %q...\n", name)

	if err := doExport(ctx, w, opts, name, outputPath, inst, paths, be, client, tui.NoopNotifier{}); err != nil {
		return err
	}

	printExportSummary(w, outputPath, inst, opts.Snapshot)
	return nil
}

// ---------------------------------------------------------------------------
// TUI path
// ---------------------------------------------------------------------------

func runExportTUI(ctx context.Context, opts *Options, name, outputPath string, inst *config.Instance, paths *config.Paths, be backend.Backend, client rpc.PrivilegeClient) error {
	diskStep := "Flatten disk"
	if opts.Snapshot {
		diskStep = "Copy disk (snapshot)"
	}

	steps := []tui.Step{
		{Name: "Prepare export"},
		{Name: diskStep},
		{Name: "Copy configuration files"},
		{Name: "Create archive"},
	}

	done := tui.DoneConfig{
		SuccessMsg: "Export complete: " + outputPath,
	}

	err := tui.Run("abox export: "+name, steps, done, func(out io.Writer, errOut io.Writer, notify tui.PhaseNotifier) error {
		f := opts.Factory
		f.IO.SetOutputSplit(out, errOut)
		defer f.IO.RestoreOutput()
		old := logging.StderrWriter().Swap(errOut)
		defer logging.StderrWriter().Swap(old)
		return doExport(ctx, out, opts, name, outputPath, inst, paths, be, client, notify)
	})
	if err != nil {
		return err
	}

	// Post-TUI summary (archive size, snapshot note)
	w := opts.Factory.IO.Out
	printExportSummary(w, outputPath, inst, opts.Snapshot)
	return nil
}

// ---------------------------------------------------------------------------
// Unified work function
// ---------------------------------------------------------------------------

func doExport(ctx context.Context, w io.Writer, opts *Options, name, outputPath string, inst *config.Instance, paths *config.Paths, be backend.Backend, client rpc.PrivilegeClient, notify tui.PhaseNotifier) error {
	// Phase 0: Prepare
	notify.PhaseStart(0)

	tempDir, err := os.MkdirTemp("", "abox-export-")
	if err != nil {
		notify.PhaseDone(0, err)
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	notify.PhaseDone(0, nil)

	// Phase 1: Disk
	notify.PhaseStart(1)
	if opts.Snapshot {
		fmt.Fprintln(w, "Copying disk (snapshot mode)...")
	} else {
		fmt.Fprintln(w, "Flattening disk (this may take a while)...")
	}
	diskPath := filepath.Join(tempDir, "disk.qcow2")
	if err := be.Disk().Export(ctx, client, diskPath, paths, opts.Snapshot); err != nil {
		notify.PhaseDone(1, err)
		return fmt.Errorf("failed to export disk: %w", err)
	}
	notify.PhaseDone(1, nil)

	// Phase 2: Config files
	notify.PhaseStart(2)
	fmt.Fprintln(w, "Copying configuration files...")

	if err := copyFile(paths.Config, filepath.Join(tempDir, "config.yaml")); err != nil {
		notify.PhaseDone(2, err)
		return fmt.Errorf("failed to copy config: %w", err)
	}
	if err := copyFile(paths.SSHKey, filepath.Join(tempDir, "id_ed25519")); err != nil {
		notify.PhaseDone(2, err)
		return fmt.Errorf("failed to copy SSH private key: %w", err)
	}
	if err := copyFile(paths.SSHKey+".pub", filepath.Join(tempDir, "id_ed25519.pub")); err != nil {
		notify.PhaseDone(2, err)
		return fmt.Errorf("failed to copy SSH public key: %w", err)
	}
	if err := copyFile(paths.Allowlist, filepath.Join(tempDir, "allowlist.conf")); err != nil {
		notify.PhaseDone(2, err)
		return fmt.Errorf("failed to copy allowlist: %w", err)
	}

	// Create manifest
	manifest := Manifest{
		Version:     1,
		Format:      "abox-archive",
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		AboxVersion: version.Version,
		Snapshot:    opts.Snapshot,
		Instance: ManifestInstance{
			Name:   inst.Name,
			CPUs:   inst.CPUs,
			Memory: inst.Memory,
			Base:   inst.Base,
			Disk:   inst.Disk,
		},
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		notify.PhaseDone(2, err)
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "manifest.json"), manifestData, 0o644); err != nil { //nolint:gosec // manifest in temp dir
		notify.PhaseDone(2, err)
		return fmt.Errorf("failed to write manifest: %w", err)
	}
	notify.PhaseDone(2, nil)

	// Phase 3: Archive
	notify.PhaseStart(3)
	fmt.Fprintln(w, "Creating archive...")
	if err := createTarGz(outputPath, tempDir); err != nil {
		notify.PhaseDone(3, err)
		return fmt.Errorf("failed to create archive: %w", err)
	}
	notify.PhaseDone(3, nil)

	var archiveSize int64
	if info, err := os.Stat(outputPath); err == nil {
		archiveSize = info.Size()
	}
	logging.AuditInstance(name, logging.ActionExport, "output", outputPath, "snapshot", opts.Snapshot, "size", archiveSize)

	return nil
}

// printExportSummary prints archive size and snapshot note after the work completes.
func printExportSummary(w io.Writer, outputPath string, inst *config.Instance, snapshot bool) {
	info, err := os.Stat(outputPath)
	if err == nil {
		fmt.Fprintf(w, "Archive size: %s\n", formatSize(info.Size()))
	}
	if snapshot {
		fmt.Fprintf(w, "\nNote: This is a snapshot archive. The target machine must have\n")
		fmt.Fprintf(w, "the base image %q installed.\n", inst.Base)
	}
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}

	// Preserve permissions
	info, err := in.Stat()
	if err != nil {
		out.Close()
		return err
	}
	if err := out.Chmod(info.Mode()); err != nil {
		out.Close()
		return err
	}

	if _, err = io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// createTarGz creates a gzipped tar archive from a directory.
func createTarGz(archivePath, sourceDir string) error {
	file, err := os.Create(archivePath)
	if err != nil {
		return err
	}

	gw := gzip.NewWriter(file)
	tw := tar.NewWriter(gw)

	walkErr := filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == sourceDir {
			return nil
		}
		// Skip symlinks to prevent following symlinks into untrusted locations
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		return writeTarEntry(tw, sourceDir, path, d)
	})

	// Close writers in reverse order, checking errors
	twErr := tw.Close()
	gwErr := gw.Close()
	fileErr := file.Close()

	if walkErr != nil {
		return walkErr
	}
	if twErr != nil {
		return twErr
	}
	if gwErr != nil {
		return gwErr
	}
	return fileErr
}

// writeTarEntry writes a single directory entry to the tar writer.
func writeTarEntry(tw *tar.Writer, sourceDir, path string, d fs.DirEntry) error {
	info, err := d.Info()
	if err != nil {
		return err
	}

	relPath, err := filepath.Rel(sourceDir, path)
	if err != nil {
		return err
	}

	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = relPath

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	if !info.IsDir() {
		return writeTarFileContent(tw, path)
	}
	return nil
}

// writeTarFileContent copies a file's content into the tar writer.
func writeTarFileContent(tw *tar.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

// formatSize formats a size in bytes as a human-readable string.
func formatSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}
