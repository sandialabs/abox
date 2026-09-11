package remove

import (
	"fmt"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/secretstore"
	"github.com/sandialabs/abox/internal/validation"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// Options holds the options for the remove command.
type Options struct {
	Factory *factory.Factory
	Name    string
	Key     string
}

// NewCmdRemove creates the `abox secrets remove` command.
func NewCmdRemove(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:               "remove <instance> <key>",
		Aliases:           []string{"rm"},
		Short:             "Remove a stored secret",
		Long:              "Remove a secret key from the instance's host-side secret store.",
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completion.Sequence(completion.AllInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			opts.Key = args[1]
			if runF != nil {
				return runF(opts)
			}
			return runRemove(opts)
		},
	}

	return cmd
}

func runRemove(opts *Options) error {
	f := opts.Factory
	if !config.Exists(opts.Name) {
		return fmt.Errorf("instance %q does not exist", opts.Name)
	}
	if err := validation.ValidateSecretKey(opts.Key); err != nil {
		return err
	}
	paths, err := config.GetPaths(opts.Name)
	if err != nil {
		return err
	}
	if err := secretstore.New(paths.Secrets).Delete(opts.Key); err != nil {
		return fmt.Errorf("failed to remove secret: %w", err)
	}

	logging.AuditInstance(opts.Name, logging.ActionSecretRemove, "key", opts.Key)

	fmt.Fprintf(f.IO.Out, "Removed secret %q for instance %q.\n", opts.Key, opts.Name)
	return nil
}
