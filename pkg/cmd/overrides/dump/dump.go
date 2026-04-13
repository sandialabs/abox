// Package dump provides the overrides dump command.
package dump

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// availableKeys returns sorted override key names from registered backends.
func availableKeys() []string {
	reg := backend.OverrideDefaults()
	keys := make([]string, 0, len(reg))
	for k := range reg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// keyHelp returns a formatted description of all registered override keys.
func keyHelp() string {
	keys := availableKeys()
	reg := backend.OverrideDefaults()
	var b strings.Builder
	for _, k := range keys {
		entry := reg[k]
		fmt.Fprintf(&b, "  %s\n", k)
		for line := range strings.SplitSeq(entry.Description, "\n") {
			fmt.Fprintf(&b, "    %s\n", line)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// NewCmdDump creates the overrides dump command.
func NewCmdDump(f *factory.Factory) *cobra.Command {
	return &cobra.Command{
		Use:   "dump <key>",
		Short: "Output the built-in default for an override key",
		Long: fmt.Sprintf(`Output the built-in default for an override key.

This lets you create a custom override by starting from the default
and modifying it. The output is written to stdout so it can be
redirected to a file.

Available keys:

%sExample:
  abox overrides dump libvirt.template > domain.xml.tmpl`, keyHelp()),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			reg := backend.OverrideDefaults()
			entry, ok := reg[key]
			if !ok {
				return fmt.Errorf("unknown override key %q; available keys: %s",
					key, strings.Join(availableKeys(), ", "))
			}
			fmt.Fprint(f.IO.Out, entry.Fn())
			return nil
		},
	}
}
