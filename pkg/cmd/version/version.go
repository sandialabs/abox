// Package version provides the version command.
package version

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sandialabs/abox/internal/version"
	"github.com/sandialabs/abox/pkg/cmd/factory"
)

// Options holds the options for the version command.
type Options struct {
	Factory *factory.Factory
}

// NewCmdVersion creates the version command.
func NewCmdVersion(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	return &cobra.Command{
		Use:   "version",
		Short: "Show abox version information",
		Long:  "Display version, commit, and build date information.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runF != nil {
				return runF(opts)
			}
			fmt.Fprintf(f.IO.Out, "abox %s (commit: %s, built: %s)\n",
				version.Version, version.Commit, version.Date)
			return nil
		},
	}
}
