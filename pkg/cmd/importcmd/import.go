package importcmd

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/tui"
	"github.com/sandialabs/abox/pkg/cmd/export"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// Options holds the options for the import command.
type Options struct {
	Factory     *factory.Factory
	CPUs        int
	Memory      int
	ArchivePath string // Archive file path (positional arg)
	NewName     string // Optional new instance name (positional arg)
}

// NewCmdImport creates a new import command.
func NewCmdImport(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "import <archive-path> [new-name]",
		Short: "Import an abox instance from an archive",
		Long: `Import an abox instance from a .abox.tar.gz archive.

The instance will be created with new network resources (subnet, ports, MAC)
to avoid conflicts with existing instances.

If importing a snapshot archive, the corresponding base image must already
be installed on this machine.`,
		Example: `  abox import dev.abox.tar.gz             # Import with original name
  abox import dev.abox.tar.gz dev2        # Import with a new name
  abox import dev.abox.tar.gz --cpus 4    # Override resource settings`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.ArchivePath = args[0]
			if len(args) > 1 {
				opts.NewName = args[1]
			}
			if runF != nil {
				return runF(opts)
			}
			return runImport(cmd.Context(), opts, opts.ArchivePath, opts.NewName)
		},
	}

	cmd.Flags().IntVar(&opts.CPUs, "cpus", 0, "Override CPU count")
	cmd.Flags().IntVar(&opts.Memory, "memory", 0, "Override memory size (MB)")

	return cmd
}

func runImport(ctx context.Context, opts *Options, archivePath, newName string) error {
	// Check archive exists
	if _, err := os.Stat(archivePath); os.IsNotExist(err) {
		return fmt.Errorf("archive not found: %s", archivePath)
	}

	// Peek at manifest to determine instance name without full extraction
	manifest, err := peekManifest(archivePath)
	if err != nil {
		return err
	}

	// Determine instance name
	name := newName
	if name == "" {
		name = manifest.Instance.Name
	}

	// Check if name already taken
	if config.Exists(name) {
		return &cmdutil.ErrHint{
			Err:  fmt.Errorf("instance %q already exists", name),
			Hint: fmt.Sprintf("Use a different name: abox import %s <new-name>", archivePath),
		}
	}

	// For snapshot archives, verify base image exists
	if manifest.Snapshot {
		paths, err := config.GetPaths(name)
		if err != nil {
			return err
		}
		baseImage := filepath.Join(paths.BaseImages, manifest.Instance.Base+".qcow2")
		if _, err := os.Stat(baseImage); os.IsNotExist(err) {
			return &cmdutil.ErrHint{
				Err:  fmt.Errorf("base image %q not found", manifest.Instance.Base),
				Hint: "This is a snapshot archive that requires the base image.\nInstall it with: abox base pull " + manifest.Instance.Base,
			}
		}
	}

	// Get privilege client early - this is where the single password prompt happens
	client, err := opts.Factory.PrivilegeClientFor(name)
	if err != nil {
		return fmt.Errorf("failed to get privilege client: %w", err)
	}

	if opts.Factory.IO.IsTerminal() {
		return runImportTUI(ctx, opts, archivePath, name, manifest, client)
	}
	return runImportPlain(ctx, opts, archivePath, name, manifest, client)
}

// ---------------------------------------------------------------------------
// Plain text path (non-TTY or pipe)
// ---------------------------------------------------------------------------

func runImportPlain(ctx context.Context, opts *Options, archivePath, name string, manifest *export.Manifest, client rpc.PrivilegeClient) error {
	w := opts.Factory.IO.Out
	fmt.Fprintf(w, "Importing from %s...\n", archivePath)

	if err := doImport(ctx, w, opts, archivePath, name, manifest, client, tui.NoopNotifier{}); err != nil {
		return err
	}

	fmt.Fprintf(w, "\nInstance %q imported successfully!\n", name)
	return nil
}

// ---------------------------------------------------------------------------
// TUI path
// ---------------------------------------------------------------------------

func runImportTUI(ctx context.Context, opts *Options, archivePath, name string, manifest *export.Manifest, client rpc.PrivilegeClient) error {
	steps := []tui.Step{
		{Name: "Extract archive"},
		{Name: "Validate manifest"},
		{Name: "Allocate resources"},
		{Name: "Copy disk image"},
		{Name: "Create network & VM"},
	}

	done := tui.DoneConfig{
		SuccessMsg: fmt.Sprintf("Instance %q imported!", name),
		HintLines: []string{
			"Start: abox start " + name,
			"SSH:   abox ssh " + name,
		},
	}

	err := tui.Run("abox import: "+name, steps, done, func(out io.Writer, errOut io.Writer, notify tui.PhaseNotifier) error {
		f := opts.Factory
		f.IO.SetOutputSplit(out, errOut)
		defer f.IO.RestoreOutput()
		old := logging.StderrWriter().Swap(errOut)
		defer logging.StderrWriter().Swap(old)
		return doImport(ctx, out, opts, archivePath, name, manifest, client, notify)
	})
	if err != nil {
		return err
	}

	// Post-TUI: print subnet details
	inst, _, err := config.Load(name)
	if err == nil {
		w := opts.Factory.IO.Out
		fmt.Fprintf(w, "Subnet: %s (gateway: %s)\n", inst.Subnet, inst.Gateway)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Unified work function
// ---------------------------------------------------------------------------

func doImport(ctx context.Context, w io.Writer, opts *Options, archivePath, name string, manifest *export.Manifest, client rpc.PrivilegeClient, notify tui.PhaseNotifier) error {
	// Phase 0: Extract archive
	notify.PhaseStart(0)
	fmt.Fprintln(w, "Extracting archive...")
	tempDir, err := extractArchive(archivePath)
	if err != nil {
		notify.PhaseDone(0, err)
		return err
	}
	defer os.RemoveAll(tempDir)
	notify.PhaseDone(0, nil)

	// Phase 1: Validate manifest
	notify.PhaseStart(1)
	if err := validateExtractedManifest(tempDir); err != nil {
		notify.PhaseDone(1, err)
		return err
	}
	notify.PhaseDone(1, nil)

	// Phase 2: Allocate resources
	notify.PhaseStart(2)
	fmt.Fprintf(w, "Creating instance %q...\n", name)
	inst, paths, cleanup, be, err := allocateResources(opts, name, manifest, w)
	if err != nil {
		notify.PhaseDone(2, err)
		return err
	}
	cleanup.client = client
	defer cleanup.run()
	notify.PhaseDone(2, nil)

	// Phase 3: Copy disk and config files
	notify.PhaseStart(3)
	if err := copyDiskAndConfig(ctx, w, tempDir, manifest, paths, inst, be, client, cleanup); err != nil {
		notify.PhaseDone(3, err)
		return err
	}
	notify.PhaseDone(3, nil)

	// Phase 4: Create network & VM
	notify.PhaseStart(4)
	if err := createNetworkAndVM(ctx, w, be, inst, paths, cleanup); err != nil {
		notify.PhaseDone(4, err)
		return err
	}
	notify.PhaseDone(4, nil)

	logging.AuditInstance(name, logging.ActionImport, "archive", archivePath, "snapshot", manifest.Snapshot)
	return nil
}

// extractArchive creates a temp directory and extracts the archive into it.
func extractArchive(archivePath string) (string, error) {
	runtimeDir, err := config.RuntimeDir()
	if err != nil {
		return "", fmt.Errorf("cannot import: %w", err)
	}
	tempDir, err := os.MkdirTemp(runtimeDir, "abox-import-")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}
	if err := extractTarGz(archivePath, tempDir); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("failed to extract archive: %w", err)
	}
	return tempDir, nil
}

// validateExtractedManifest reads and validates the manifest from an extracted archive.
func validateExtractedManifest(tempDir string) error {
	manifestPath := filepath.Join(tempDir, "manifest.json")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return &cmdutil.ErrHint{
			Err:  fmt.Errorf("failed to read manifest: %w", err),
			Hint: "Is this a valid abox archive?",
		}
	}

	var extractedManifest export.Manifest
	if err := json.Unmarshal(manifestData, &extractedManifest); err != nil {
		return fmt.Errorf("failed to parse manifest: %w", err)
	}
	if extractedManifest.Format != "abox-archive" {
		return fmt.Errorf("invalid archive format: %s", extractedManifest.Format)
	}
	if extractedManifest.Version != 1 {
		return fmt.Errorf("unsupported archive version: %d", extractedManifest.Version)
	}
	return nil
}

// allocateResources sets up paths, backend, subnet, and builds the instance config.
func allocateResources(opts *Options, name string, manifest *export.Manifest, w io.Writer) (*config.Instance, *config.Paths, *cleanupState, backend.Backend, error) {
	be, err := opts.Factory.AutoDetectBackend()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to get backend: %w", err)
	}

	paths, err := config.GetPathsWithStorage(name, be.StorageDir())
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if err := config.EnsureDirs(paths); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create directories: %w", err)
	}

	cleanup := &cleanupState{paths: paths, name: name, errOut: w}

	subnet, gateway, thirdOctet, err := config.AllocateSubnet("")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to allocate subnet: %w", err)
	}

	cpus := manifest.Instance.CPUs
	if opts.CPUs > 0 {
		cpus = opts.CPUs
	}
	memory := manifest.Instance.Memory
	if opts.Memory > 0 {
		memory = opts.Memory
	}

	bridge := be.ResourceNames(name).Network
	cleanup.bridge = bridge
	cleanup.be = be

	inst := &config.Instance{
		Version: config.CurrentInstanceVersion,
		Name:    name,
		Backend: be.Name(),
		CPUs:    cpus,
		Memory:  memory,
		Base:    manifest.Instance.Base,
		Subnet:  subnet,
		Gateway: gateway,
		Bridge:  bridge,
		DNS: config.DNSConfig{
			Port:     0,
			Upstream: "8.8.8.8:53",
		},
		SSHKey:     paths.SSHKey,
		Disk:       manifest.Instance.Disk,
		MACAddress: be.GenerateMAC(),
		IPAddress:  fmt.Sprintf("10.10.%d.10", thirdOctet),
		StorageDir: be.StorageDir(),
	}

	return inst, paths, cleanup, be, nil
}

// copyDiskAndConfig copies the disk image and configuration files from the extracted archive.
func copyDiskAndConfig(ctx context.Context, w io.Writer, tempDir string, manifest *export.Manifest, paths *config.Paths, inst *config.Instance, be backend.Backend, client rpc.PrivilegeClient, cleanup *cleanupState) error {
	fmt.Fprintln(w, "Copying disk image...")
	srcDisk := filepath.Join(tempDir, "disk.qcow2")
	if err := be.Disk().Import(ctx, client, srcDisk, inst, paths, manifest.Snapshot); err != nil {
		return fmt.Errorf("failed to import disk: %w", err)
	}
	cleanup.diskCreated = true

	fmt.Fprintln(w, "Copying configuration files...")
	if err := copyFile(filepath.Join(tempDir, "id_ed25519"), paths.SSHKey); err != nil {
		return fmt.Errorf("failed to copy SSH private key: %w", err)
	}
	if err := os.Chmod(paths.SSHKey, 0o600); err != nil {
		return fmt.Errorf("failed to set SSH key permissions: %w", err)
	}
	if err := copyFile(filepath.Join(tempDir, "id_ed25519.pub"), paths.SSHKey+".pub"); err != nil {
		return fmt.Errorf("failed to copy SSH public key: %w", err)
	}
	if err := copyFile(filepath.Join(tempDir, "allowlist.conf"), paths.Allowlist); err != nil {
		return fmt.Errorf("failed to copy allowlist: %w", err)
	}

	if err := config.Save(inst, paths); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}
	cleanup.configCreated = true
	return nil
}

// createNetworkAndVM creates the libvirt network and VM definition.
func createNetworkAndVM(ctx context.Context, w io.Writer, be backend.Backend, inst *config.Instance, paths *config.Paths, cleanup *cleanupState) error {
	fmt.Fprintln(w, "Creating network...")
	if err := be.Network().Create(ctx, inst); err != nil {
		return fmt.Errorf("failed to create network: %w", err)
	}
	cleanup.networkCreated = true

	fmt.Fprintln(w, "Creating VM...")
	vmOpts := backend.VMCreateOptions{}
	if err := be.VM().Create(ctx, inst, paths, vmOpts); err != nil {
		return fmt.Errorf("failed to create VM: %w", err)
	}
	cleanup.domainCreated = true

	cleanup.success = true
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// peekManifest reads just the manifest.json from a tar.gz archive without
// extracting the full archive.
func peekManifest(archivePath string) (*export.Manifest, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open archive: %w", err)
	}
	defer file.Close()

	gr, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read archive: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read archive: %w", err)
		}

		if header.Name == "manifest.json" {
			data, err := io.ReadAll(io.LimitReader(tr, 1<<20)) // 1MB limit
			if err != nil {
				return nil, fmt.Errorf("failed to read manifest: %w", err)
			}

			var manifest export.Manifest
			if err := json.Unmarshal(data, &manifest); err != nil {
				return nil, fmt.Errorf("failed to parse manifest: %w", err)
			}
			if manifest.Format != "abox-archive" {
				return nil, fmt.Errorf("invalid archive format: %s", manifest.Format)
			}
			return &manifest, nil
		}
	}

	return nil, &cmdutil.ErrHint{
		Err:  errors.New("manifest.json not found in archive"),
		Hint: "Is this a valid abox archive?",
	}
}

// cleanupState tracks resources to clean up on failure.
type cleanupState struct {
	paths          *config.Paths
	name           string
	bridge         string
	be             backend.Backend
	client         rpc.PrivilegeClient
	errOut         io.Writer
	diskCreated    bool
	configCreated  bool
	networkCreated bool
	domainCreated  bool
	success        bool
}

func (c *cleanupState) run() {
	if c.success {
		return
	}

	w := c.errOut
	if w == nil {
		w = os.Stderr
	}
	fmt.Fprintln(w, "Cleaning up after failure...")

	ctx := context.Background()

	if c.domainCreated && c.be != nil {
		_ = c.be.VM().Remove(ctx, c.name)
	}
	if c.networkCreated && c.be != nil {
		_ = c.be.Network().Delete(ctx, c.bridge)
	}
	if c.diskCreated && c.be != nil && c.client != nil {
		_ = c.be.Disk().Delete(ctx, c.client, c.paths)
	}
	if c.configCreated || c.diskCreated {
		os.RemoveAll(c.paths.Instance)
	}
}

// extractTarGz extracts a gzipped tar archive to a directory.
func extractTarGz(archivePath, destDir string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()

	gr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if err := extractTarEntry(tr, header, destDir); err != nil {
			return err
		}
	}

	return nil
}

// extractTarEntry extracts a single tar entry to the destination directory.
func extractTarEntry(tr *tar.Reader, header *tar.Header, destDir string) error {
	targetPath := filepath.Join(destDir, header.Name) //nolint:gosec // G305: path traversal checked below

	// Security check: ensure path doesn't escape destDir
	cleanTarget := filepath.Clean(targetPath)
	cleanDest := filepath.Clean(destDir) + string(os.PathSeparator)
	if !strings.HasPrefix(cleanTarget, cleanDest) && cleanTarget != filepath.Clean(destDir) {
		return fmt.Errorf("invalid tar entry: %s", header.Name)
	}

	switch header.Typeflag {
	case tar.TypeDir:
		return os.MkdirAll(targetPath, os.FileMode(header.Mode)&0o777) //nolint:gosec // mode is masked to 0o777
	case tar.TypeReg:
		return extractTarFile(tr, header, targetPath)
	}
	return nil
}

// extractTarFile extracts a regular file from a tar entry.
func extractTarFile(tr *tar.Reader, header *tar.Header, targetPath string) error {
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil { //nolint:gosec // directory for extracted file
		return err
	}

	f, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode)&0o777) //nolint:gosec // mode is masked to 0o777
	if err != nil {
		return err
	}

	if _, err := io.Copy(f, io.LimitReader(tr, header.Size)); err != nil {
		f.Close()
		return err
	}
	return f.Close()
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
