package view

import (
	"fmt"

	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

// Options holds the options for the view command.
type Options struct {
	Factory  *factory.Factory
	Exporter *cmdutil.Exporter
	Name     string
}

// NewCmdView creates a new config view command.
func NewCmdView(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "view <instance>",
		Short: "View instance configuration",
		Long:  `Display the configuration for an abox instance.`,
		Example: `  abox config view dev                     # Show instance config
  abox config view dev --json              # JSON output
  abox config view dev --jq '.cpus'        # Extract a specific field`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completion.Sequence(completion.AllInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if runF != nil {
				return runF(opts)
			}
			return runView(opts, opts.Name)
		},
	}

	opts.Exporter = cmdutil.AddJSONFlags(cmd)

	return cmd
}

func runView(opts *Options, name string) error {
	inst, _, err := instance.LoadRequired(name)
	if err != nil {
		return err
	}

	w := opts.Factory.IO.Out

	if opts.Exporter.Enabled() {
		return opts.Exporter.Write(w, inst)
	}

	data, err := yaml.Marshal(inst)
	if err != nil {
		return err
	}
	fmt.Fprint(w, string(data))

	return nil
}
