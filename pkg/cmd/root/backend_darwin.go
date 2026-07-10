//go:build darwin

package root

import (
	"github.com/spf13/cobra"

	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/helper"
	"github.com/sandialabs/abox/pkg/cmd/teardownpf"

	// Register the macOS (vfkit) backend on darwin.
	_ "github.com/sandialabs/abox/internal/backend/vfkit"
)

// addPlatformCommands registers macOS-specific subcommands.
func addPlatformCommands(cmd *cobra.Command) {
	cmd.AddCommand(helper.NewCmdHelper())
}

// addPlatformGroupedCommands registers macOS-only commands that belong in a
// help group (currently just teardown-pf in the utilities group).
func addPlatformGroupedCommands(cmd *cobra.Command, f *factory.Factory) {
	addGroupedCommand(cmd, teardownpf.NewCmdTeardownPF(f, nil), groupUtilities)
}

// addPlatformFileCommands is a no-op on macOS. The mount/unmount commands rely
// on FUSE/sshfs, which abox does not support on macOS (macFUSE is a kernel
// extension requiring Reduced Security — a poor fit for a sandboxing tool). Use
// `abox scp` to move files, or `abox remote` (registered for all platforms in
// addSubcommands) to work with a git repository inside the VM.
func addPlatformFileCommands(_ *cobra.Command, _ *factory.Factory) {}
