package list

import (
	"fmt"
	"time"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/mountutil"
	"github.com/sandialabs/abox/internal/tableprinter"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/mount/shared"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// mountJSON is the JSON representation of a mount.
type mountJSON struct {
	LocalPath  string    `json:"local_path"`
	RemotePath string    `json:"remote_path"`
	MountedAt  time.Time `json:"mounted_at"`
	Status     string    `json:"status"`
}

// Options holds the options for the mount list command.
type Options struct {
	Factory  *factory.Factory
	Exporter *cmdutil.Exporter
	Name     string
}

// NewCmdList creates a new mount list command.
func NewCmdList(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:     "list <instance>",
		Aliases: []string{"ls"},
		Short:   "List recorded mounts",
		Long:    `List all SSHFS mounts recorded for an instance.`,
		Example: `  abox mount list dev
  abox mount ls dev`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completion.Sequence(completion.AllInstances()),
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

	mounts, err := shared.GetMounts(paths.Instance)
	if err != nil {
		return fmt.Errorf("failed to load mounts: %w", err)
	}

	items := collectMounts(mounts)

	if exporter.Enabled() {
		return exporter.Write(f.IO.Out, items)
	}

	if len(items) == 0 {
		return &cmdutil.NoResultsError{Message: "no mounts for " + name}
	}

	return renderMountsTable(f, name, items)
}

// collectMounts converts mount records into JSON-ready items, resolving each
// mount's live status via mountutil.IsMounted (a record can outlive its mount).
func collectMounts(mounts []shared.MountEntry) []mountJSON {
	items := make([]mountJSON, 0, len(mounts))
	for _, m := range mounts {
		status := "stale"
		if mountutil.IsMounted(m.LocalPath) {
			status = "mounted"
		}
		items = append(items, mountJSON{
			LocalPath:  m.LocalPath,
			RemotePath: m.RemotePath,
			MountedAt:  m.MountedAt,
			Status:     status,
		})
	}
	return items
}

// renderMountsTable renders mounts as a TTY table.
func renderMountsTable(f *factory.Factory, name string, items []mountJSON) error {
	f.IO.StartPager()
	defer f.IO.StopPager()

	out := f.IO.Out
	fmt.Fprintf(out, "Mounts for %s:\n", name)
	tp := tableprinter.New(out, f.ColorScheme, f.IO.IsTerminal())
	tp.AddHeader("LOCAL PATH", "REMOTE PATH", "MOUNTED AT", "STATUS")

	for _, item := range items {
		tp.AddRow(item.LocalPath, item.RemotePath, item.MountedAt.Format("2006-01-02 15:04:05"), item.Status)
	}

	tp.Render()
	return nil
}
