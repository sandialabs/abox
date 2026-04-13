package list

import (
	"fmt"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/tableprinter"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/forward/shared"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// forwardJSON is the JSON representation of a port forward.
type forwardJSON struct {
	HostPort  int    `json:"host_port"`
	GuestPort int    `json:"guest_port"`
	Direction string `json:"direction"`
	Status    string `json:"status"`
}

// Options holds the options for the forward list command.
type Options struct {
	Factory  *factory.Factory
	Exporter *cmdutil.Exporter
	Name     string
}

// NewCmdList creates a new forward list command.
func NewCmdList(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:     "list <instance>",
		Aliases: []string{"ls"},
		Short:   "List active port forwards",
		Long:    `List all port forwards for an instance.`,
		Example: `  abox forward list dev
  abox forward ls dev`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completion.Sequence(completion.RunningInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if runF != nil {
				return runF(opts)
			}
			return runList(f, opts.Exporter, args[0])
		},
	}

	opts.Exporter = cmdutil.AddJSONFlags(cmd)

	return cmd
}

func runList(f *factory.Factory, exporter *cmdutil.Exporter, name string) error {
	if !config.Exists(name) {
		return fmt.Errorf("instance %q does not exist", name)
	}

	_, paths, err := config.Load(name)
	if err != nil {
		return err
	}

	forwards, err := shared.LoadForwards(paths.Instance)
	if err != nil {
		return fmt.Errorf("failed to load forwards: %w", err)
	}

	items := collectForwards(forwards)

	if exporter.Enabled() {
		return exporter.Write(f.IO.Out, items)
	}

	if len(items) == 0 {
		return &cmdutil.NoResultsError{Message: "no port forwards for " + name}
	}

	return renderForwardsTable(f, name, items, forwards)
}

// collectForwards converts shared.ForwardsFile entries into JSON-ready items.
func collectForwards(forwards *shared.ForwardsFile) []forwardJSON {
	items := make([]forwardJSON, 0, len(forwards.Forwards))
	for _, fwd := range forwards.Forwards {
		direction := "host→guest"
		if fwd.Reverse {
			direction = "guest→host"
		}
		status := "inactive"
		if shared.IsPIDRunning(fwd.PID) {
			status = "active"
		}
		items = append(items, forwardJSON{
			HostPort:  fwd.HostPort,
			GuestPort: fwd.GuestPort,
			Direction: direction,
			Status:    status,
		})
	}
	return items
}

// renderForwardsTable renders port forwards as a TTY table.
func renderForwardsTable(f *factory.Factory, name string, items []forwardJSON, forwards *shared.ForwardsFile) error {
	f.IO.StartPager()
	defer f.IO.StopPager()

	out := f.IO.Out
	fmt.Fprintf(out, "Port forwards for %s:\n", name)
	tp := tableprinter.New(out, f.ColorScheme, f.IO.IsTerminal())
	tp.AddHeader("HOST", "GUEST", "DIRECTION", "STATUS")

	for _, item := range items {
		status := resolveStatus(item, forwards)
		tp.AddRow(item.HostPort, item.GuestPort, item.Direction, status)
	}

	tp.Render()
	return nil
}

// resolveStatus returns the display status for a forward, including PID for active forwards.
func resolveStatus(item forwardJSON, forwards *shared.ForwardsFile) string {
	if item.Status != "active" {
		return item.Status
	}
	for _, fwd := range forwards.Forwards {
		if fwd.HostPort == item.HostPort && fwd.GuestPort == item.GuestPort {
			return fmt.Sprintf("active (pid %d)", fwd.PID)
		}
	}
	return item.Status
}
