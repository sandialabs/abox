package list

import (
	"fmt"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/tableprinter"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// instanceJSON is the JSON representation of an instance in the list.
type instanceJSON struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	IP     string `json:"ip"`
	Subnet string `json:"subnet"`
	CPUs   int    `json:"cpus"`
	Memory int    `json:"memory_mb"`
}

// Options holds the options for the list command.
type Options struct {
	Factory  *factory.Factory
	Exporter *cmdutil.Exporter
}

// NewCmdList creates a new list command.
func NewCmdList(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all abox instances",
		Long: `List all abox instances with their current state, IP address, and subnet.

Instances are shown in a table with columns for name, state (running, shut off,
etc.), IP address, and subnet. Use --json or --jq for machine-readable output.`,
		Example: `  abox list                                # List all instances
  abox ls                                  # Short alias
  abox list --json                         # JSON output
  abox list --jq '.[].name'               # Extract instance names`,
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if runF != nil {
				return runF(opts)
			}
			return RunList(f, opts.Exporter)
		},
	}

	opts.Exporter = cmdutil.AddJSONFlags(cmd)

	return cmd
}

// RunList lists all instances. Exported for use by status command.
func RunList(f *factory.Factory, exporter *cmdutil.Exporter) error {
	if f == nil {
		f = factory.New()
	}

	instances, err := config.List()
	if err != nil {
		return err
	}

	if len(instances) == 0 {
		if exporter.Enabled() {
			return exporter.Write(f.IO.Out, []instanceJSON{})
		}
		return &cmdutil.NoResultsError{Message: "no instances found"}
	}

	items := collectInstances(f, instances)

	if exporter.Enabled() {
		return exporter.Write(f.IO.Out, items)
	}

	return renderTable(f, items)
}

// collectInstances gathers instance data for all named instances.
func collectInstances(f *factory.Factory, instances []string) []instanceJSON {
	var items []instanceJSON
	for _, name := range instances {
		items = append(items, collectInstance(f, name))
	}
	return items
}

// collectInstance gathers data for a single instance.
func collectInstance(f *factory.Factory, name string) instanceJSON {
	item := instanceJSON{Name: name, State: "error", IP: "-"}

	inst, _, err := config.Load(name)
	if err != nil {
		return item
	}

	item.Subnet = inst.Subnet
	item.CPUs = inst.CPUs
	item.Memory = inst.Memory

	be, err := f.BackendFor(name)
	if err != nil {
		be, err = backend.AutoDetect()
		if err != nil {
			item.State = "unknown"
			return item
		}
	}

	state := be.VM().State(name)
	item.State = string(state)

	if state == backend.VMStateRunning {
		if addr, err := be.VM().GetIP(name); err == nil {
			item.IP = addr
		}
	}

	return item
}

// renderTable renders instance data as a TTY table with colors.
func renderTable(f *factory.Factory, items []instanceJSON) error {
	f.IO.StartPager()
	defer f.IO.StopPager()

	tp := tableprinter.New(f.IO.Out, f.ColorScheme, f.IO.IsTerminal())
	tp.AddHeader("NAME", "STATE", "IP", "SUBNET", "CPUS", "MEMORY")

	for _, item := range items {
		stateStr := colorizeState(f, item.State)

		ip := item.IP
		if ip == "" {
			ip = "-"
		}

		tp.AddRow(item.Name, stateStr, ip, item.Subnet, item.CPUs, fmt.Sprintf("%dMB", item.Memory))
	}

	tp.Render()
	return nil
}

// colorizeState applies color to a VM state string when colors are enabled.
func colorizeState(f *factory.Factory, state string) string {
	if !f.ColorScheme.Enabled() {
		return state
	}
	switch backend.VMState(state) {
	case backend.VMStateRunning:
		return f.ColorScheme.Green(state)
	case backend.VMStateStopped, backend.VMStateShutdown, backend.VMStateCrashed:
		return f.ColorScheme.Red(state)
	case backend.VMStatePaused, backend.VMStateUnknown:
		return state
	default:
		return state
	}
}
