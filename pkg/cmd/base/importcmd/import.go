package importcmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/fsutil"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/qemuimg"
	"github.com/sandialabs/abox/internal/vmrun"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// Options holds the options for the base import command.
type Options struct {
	Factory *factory.Factory
	Name    string
	Path    string
}

// NewCmdImport creates a new base import command.
func NewCmdImport(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:   "import <name> <path>",
		Short: "Import a local image as a base",
		Long: `Import a local disk image as a base image.

The image is converted to the host's base-image format (qcow2 on Linux, raw on
macOS) and stored in the base image directory. Supported input formats include
qcow2, raw, and other formats supported by qemu-img convert.`,
		Example: `  abox base import my-image ./custom.qcow2   # Import a local qcow2 image`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			opts.Path = args[1]
			if runF != nil {
				return runF(opts)
			}
			return runImport(cmd.Context(), opts.Factory.IO.Out, args[0], args[1])
		},
	}

	return cmd
}

func runImport(ctx context.Context, w io.Writer, name, sourcePath string) error {
	paths, err := config.GetPaths("")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(paths.BaseImages, 0o755); err != nil { //nolint:gosec // image dir needs 0o755 for user access
		return err
	}

	destPath := filepath.Join(paths.BaseImages, config.UserBaseImageName(name))

	// Check if source exists
	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		return fmt.Errorf("source file not found: %s", sourcePath)
	}

	// Check if dest already exists
	if _, err := os.Stat(destPath); err == nil {
		return fmt.Errorf("image %s already exists at %s", name, destPath)
	}

	fmt.Fprintf(w, "Importing %s as %s...\n", sourcePath, name)

	// Stage the untrusted source into a private, mode-0700 directory before we
	// inspect and convert it. This makes the self-containment check and the convert
	// operate on the same bytes no other process can swap between them (closing a
	// check-then-use race), and — because only this one file is staged — a split
	// image whose sibling extents were not copied fails to convert rather than
	// letting qemu-img follow a sibling symlink to a host file. fsutil.CopyFile
	// refuses a symlinked source and copies only a regular file.
	// RuntimeDirOr falls back to $TMPDIR when there is no XDG_RUNTIME_DIR /
	// /run/user/<uid> (e.g. macOS), so base import works cross-platform.
	runtimeDir := config.RuntimeDirOr(os.TempDir())
	stageDir, err := os.MkdirTemp(runtimeDir, "abox-base-import-")
	if err != nil {
		return fmt.Errorf("failed to create staging directory: %w", err)
	}
	defer os.RemoveAll(stageDir)
	staged := filepath.Join(stageDir, "source")
	if err := fsutil.CopyFile(sourcePath, staged); err != nil {
		return fmt.Errorf("failed to stage import source: %w", err)
	}

	// Validate the staged source is self-contained and detect its format by
	// CONTENT (a hostile VMDK descriptor could otherwise fold a host file into the
	// base image via a FLAT extent). base import accepts any qemu-supported source
	// format, so no format allowlist is applied here — unlike the VMware backend,
	// which additionally restricts non-VMDK sources to qcow2.
	format, err := vmrun.InspectImportSource(ctx, staged)
	if err != nil {
		return err
	}

	// Convert into a unique temp path in the SAME dest directory, then atomically
	// rename into place, so destPath only ever exists once the convert has fully
	// succeeded. An interrupted convert would otherwise leave a truncated file that
	// the os.Stat existence check above would wrongly treat as valid on re-run.
	// The rename is within the same dir, so it is atomic (not cross-device).
	tmp, err := os.CreateTemp(paths.BaseImages, config.UserBaseImageName(name)+".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp base image: %w", err)
	}
	tmpPath := tmp.Name()
	// We only need the unique name; qemu-img overwrites the file, so close it now.
	tmp.Close()
	// Best-effort cleanup on any failure before the rename; a no-op afterward.
	defer os.Remove(tmpPath)

	// Convert from the detected source format to the host's base-image format:
	// raw on macOS (vfkit cannot read qcow2), qcow2 on Linux (libvirt).
	if runtime.GOOS == "darwin" {
		if err := qemuimg.ConvertToRaw(ctx, staged, format, tmpPath); err != nil {
			return fmt.Errorf("failed to convert image to raw: %w", err)
		}
	} else if err := qemuimg.ConvertFrom(ctx, staged, tmpPath, format); err != nil {
		return fmt.Errorf("failed to convert image: %w", err)
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("failed to finalize base image: %w", err)
	}

	fmt.Fprintf(w, "Imported to: %s\n", destPath)

	logging.Audit(logging.ActionBaseImport, "path", sourcePath, "name", name)

	return nil
}
