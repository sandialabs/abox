package importcmd

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
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

The image is converted to qcow2 format and stored in the base image directory.
Supported input formats include qcow2, raw, and other formats supported by
qemu-img convert.`,
		Example: `  abox base import my-image ./custom.qcow2   # Import a local qcow2 image`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			opts.Path = args[1]
			if runF != nil {
				return runF(opts)
			}
			return runImport(opts.Factory.IO.Out, args[0], args[1])
		},
	}

	return cmd
}

func runImport(w io.Writer, name, sourcePath string) error {
	paths, err := config.GetPaths("")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(paths.BaseImages, 0o755); err != nil { //nolint:gosec // image dir needs 0o755 for user access
		return err
	}

	destPath := filepath.Join(paths.BaseImages, name+".qcow2")

	// Check if source exists
	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		return fmt.Errorf("source file not found: %s", sourcePath)
	}

	// Check if dest already exists
	if _, err := os.Stat(destPath); err == nil {
		return fmt.Errorf("image %s already exists at %s", name, destPath)
	}

	fmt.Fprintf(w, "Importing %s as %s...\n", sourcePath, name)

	// Convert to qcow2
	convertCmd := exec.Command("qemu-img", "convert", "-f", "qcow2", "-O", "qcow2", sourcePath, destPath)
	if output, err := convertCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to convert image: %s: %w", string(output), err)
	}

	fmt.Fprintf(w, "Imported to: %s\n", destPath)

	logging.Audit(logging.ActionBaseImport, "path", sourcePath, "name", name)

	return nil
}
