package list

import (
	"fmt"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/secretstore"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// Options holds the options for the list command.
type Options struct {
	Factory *factory.Factory
	Name    string
}

// NewCmdList creates the `abox secrets list` command.
func NewCmdList(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:               "list <instance>",
		Short:             "List stored secret keys (names only)",
		Long:              "List the secret key names stored for an instance. Values are never printed.",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completion.Sequence(completion.AllInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if runF != nil {
				return runF(opts)
			}
			return runList(opts)
		},
	}

	return cmd
}

func runList(opts *Options) error {
	f := opts.Factory
	if !config.Exists(opts.Name) {
		return fmt.Errorf("instance %q does not exist", opts.Name)
	}
	paths, err := config.GetPaths(opts.Name)
	if err != nil {
		return err
	}
	keys, err := secretstore.New(paths.Secrets).List()
	if err != nil {
		return fmt.Errorf("failed to read secret store: %w", err)
	}
	if len(keys) == 0 {
		fmt.Fprintf(f.IO.Out, "No secrets stored for instance %q.\n", opts.Name)
		return nil
	}
	for _, k := range keys {
		fmt.Fprintln(f.IO.Out, k)
	}
	return nil
}
