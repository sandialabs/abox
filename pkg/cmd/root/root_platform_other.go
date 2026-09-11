//go:build !linux && !darwin

package root

import (
	"github.com/spf13/cobra"

	"github.com/sandialabs/abox/pkg/cmd/factory"
)

// registerPlatformCommands registers OS-specific subcommands. On platforms other
// than Linux and macOS (currently Windows) there are no OS-specific commands:
// the SSHFS-based mount/unmount commands require a FUSE stack that is not offered
// here, and teardown-pf is macOS-only.
func registerPlatformCommands(_ *cobra.Command, _ *factory.Factory) {}
