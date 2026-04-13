package status

import (
	"fmt"
	"io"
	"os"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/monitor"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// monitorStatusJSON is the JSON representation of monitor status.
type monitorStatusJSON struct {
	Enabled       bool   `json:"enabled"`
	VMRunning     bool   `json:"vm_running,omitempty"`
	DaemonRunning bool   `json:"daemon_running"`
	EventsLogged  uint64 `json:"events_logged,omitempty"`
	LogFile       string `json:"log_file,omitempty"`
	LogSizeBytes  int64  `json:"log_size_bytes,omitempty"`
	Uptime        string `json:"uptime,omitempty"`
}

// monitorState holds the loaded state needed to render monitor status.
type monitorState struct {
	inst               *config.Instance
	paths              *config.Paths
	vmRunning          bool
	virtioSocketExists bool
}

// Options holds the options for the monitor status command.
type Options struct {
	Factory  *factory.Factory
	Exporter *cmdutil.Exporter
	Name     string
}

// NewCmdStatus creates a new monitor status command.
func NewCmdStatus(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:   "status <instance>",
		Short: "Show monitor daemon status",
		Example: `  abox monitor status dev                  # Show monitor daemon status
  abox monitor status dev --json           # JSON output`,
		Long: `Show the current status of the monitor daemon for an instance.

Displays whether the daemon is running, events logged count,
log file size, and uptime.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completion.Sequence(completion.RunningInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if runF != nil {
				return runF(opts)
			}
			return runStatus(f, opts)
		},
	}

	opts.Exporter = cmdutil.AddJSONFlags(cmd)

	return cmd
}

func runStatus(f *factory.Factory, opts *Options) error {
	name := opts.Name
	if !config.Exists(name) {
		return fmt.Errorf("instance %q does not exist", name)
	}

	if f == nil {
		f = factory.New()
	}

	state, err := loadMonitorState(f, name)
	if err != nil {
		return err
	}

	w := f.IO.Out

	if !state.inst.Monitor.Enabled {
		return writeDisabledStatus(w, opts.Exporter)
	}

	// Check if RPC socket exists (daemon running)
	if _, err := os.Stat(state.paths.MonitorRPCSocket); os.IsNotExist(err) {
		return writeDaemonNotRunning(w, state, name, opts.Exporter)
	}

	// Connect to daemon
	client, err := monitor.Dial(state.paths.MonitorRPCSocket)
	if err != nil {
		if opts.Exporter.Enabled() {
			return opts.Exporter.Write(w, monitorStatusJSON{
				Enabled:       true,
				VMRunning:     state.vmRunning,
				DaemonRunning: false,
			})
		}
		fmt.Fprintf(w, "Monitor daemon: error connecting\n")
		fmt.Fprintf(w, "  Error: %v\n", err)
		return nil
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := monitor.ClientContext()
	defer cancel()

	resp, err := client.RPCClient().Status(ctx, &rpc.Empty{})
	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}

	return writeDaemonRunning(w, state, name, resp, opts.Exporter)
}

func loadMonitorState(f *factory.Factory, name string) (*monitorState, error) {
	inst, paths, err := f.Config(name)
	if err != nil {
		return nil, err
	}

	be, err := f.BackendFor(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get backend: %w", err)
	}

	return &monitorState{
		inst:               inst,
		paths:              paths,
		vmRunning:          be.VM().IsRunning(name),
		virtioSocketExists: monitor.IsAvailable(paths.MonitorSocket),
	}, nil
}

func writeDisabledStatus(w io.Writer, exporter *cmdutil.Exporter) error {
	if exporter.Enabled() {
		return exporter.Write(w, monitorStatusJSON{Enabled: false})
	}
	fmt.Fprintf(w, "Monitor: disabled in config\n")
	fmt.Fprintf(w, "\nTo enable monitoring, add to abox.yaml:\n")
	fmt.Fprintf(w, "  monitor:\n")
	fmt.Fprintf(w, "    enabled: true\n")
	return nil
}

func writeDaemonNotRunning(w io.Writer, state *monitorState, name string, exporter *cmdutil.Exporter) error {
	if exporter.Enabled() {
		result := monitorStatusJSON{
			Enabled:       true,
			VMRunning:     state.vmRunning,
			DaemonRunning: false,
			LogFile:       state.paths.MonitorLog,
		}
		if info, statErr := os.Stat(state.paths.MonitorLog); statErr == nil {
			result.LogSizeBytes = info.Size()
		}
		return exporter.Write(w, result)
	}

	fmt.Fprintf(w, "Monitor: enabled\n")
	if state.vmRunning {
		fmt.Fprintf(w, "VM: running\n")
	} else {
		fmt.Fprintf(w, "VM: not running\n")
	}
	if state.virtioSocketExists {
		fmt.Fprintf(w, "Virtio socket: %s (exists)\n", state.paths.MonitorSocket)
	} else {
		fmt.Fprintf(w, "Virtio socket: %s (missing)\n", state.paths.MonitorSocket)
		if state.vmRunning {
			fmt.Fprintf(w, "  WARNING: VM is running but virtio socket is missing.\n")
			fmt.Fprintf(w, "  This likely means the VM was created before monitor was enabled.\n")
			fmt.Fprintf(w, "  Run: abox down --remove %s && abox up\n", name)
		}
	}
	fmt.Fprintf(w, "Monitor daemon: not running\n")
	fmt.Fprintf(w, "  Log file: %s\n", state.paths.MonitorLog)

	if info, statErr := os.Stat(state.paths.MonitorLog); statErr == nil {
		fmt.Fprintf(w, "  Log size: %s\n", formatBytes(info.Size()))
	}

	if state.vmRunning && state.virtioSocketExists {
		fmt.Fprintf(w, "\n  Daemon should be running. Try restarting: abox stop %s && abox start %s\n", name, name)
	}
	return nil
}

func writeDaemonRunning(w io.Writer, state *monitorState, name string, resp *rpc.MonitorStatus, exporter *cmdutil.Exporter) error {
	if exporter.Enabled() {
		return exporter.Write(w, monitorStatusJSON{
			Enabled:       true,
			VMRunning:     state.vmRunning,
			DaemonRunning: true,
			EventsLogged:  resp.EventsLogged,
			LogFile:       resp.LogFile,
			LogSizeBytes:  resp.LogSizeBytes,
			Uptime:        resp.Uptime,
		})
	}

	fmt.Fprintf(w, "Monitor: enabled\n")
	if state.vmRunning {
		fmt.Fprintf(w, "VM: running\n")
	} else {
		fmt.Fprintf(w, "VM: not running\n")
	}
	if state.virtioSocketExists {
		fmt.Fprintf(w, "Virtio socket: %s (exists)\n", state.paths.MonitorSocket)
	} else {
		fmt.Fprintf(w, "Virtio socket: %s (missing)\n", state.paths.MonitorSocket)
	}
	fmt.Fprintf(w, "Monitor daemon: running\n")
	fmt.Fprintf(w, "  Events logged: %d\n", resp.EventsLogged)
	fmt.Fprintf(w, "  Log file: %s\n", resp.LogFile)
	fmt.Fprintf(w, "  Log size: %s\n", formatBytes(resp.LogSizeBytes))
	fmt.Fprintf(w, "  Uptime: %s\n", resp.Uptime)

	// If daemon is running but no events have been logged, provide hints
	if resp.EventsLogged == 0 && state.vmRunning {
		fmt.Fprintf(w, "\n  No events logged yet. Check inside VM:\n")
		fmt.Fprintf(w, "    abox ssh %s\n", name)
		fmt.Fprintf(w, "    sudo systemctl status tetragon\n")
		fmt.Fprintf(w, "    sudo systemctl status abox-monitor\n")
	}

	return nil
}

// formatBytes formats bytes as a human-readable string.
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
