// Package overrides provides the overrides command for managing backend-specific overrides.
package overrides

import (
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/overrides/dump"

	"github.com/spf13/cobra"
)

// NewCmdOverrides creates a new overrides command.
func NewCmdOverrides(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "overrides",
		Short: "Manage backend-specific overrides",
		Long: `View and manage backend-specific override defaults.

Use 'abox overrides dump <key>' to output the built-in default for an
override key. This is useful for creating a custom template to use with
the overrides section in abox.yaml.

Example workflow:
  abox overrides dump libvirt.template > domain.xml.tmpl
  # Edit domain.xml.tmpl (e.g., add CPU pinning)
  # Reference it in abox.yaml:
  #   overrides:
  #     libvirt:
  #       template: domain.xml.tmpl`,
	}

	cmd.AddCommand(dump.NewCmdDump(f))

	return cmd
}
