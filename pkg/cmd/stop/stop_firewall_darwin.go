//go:build darwin

package stop

import (
	"io"

	"github.com/sandialabs/abox/internal/config"
)

// cleanupFirewallPre is a no-op on macOS.
// Phase 6 will add pfctl cleanup here.
func cleanupFirewallPre(_ io.Writer, _ *Options, _ *config.Instance, _ string) {}

// cleanupFirewallPost is a no-op on macOS.
// Phase 6 will add pfctl cleanup here.
func cleanupFirewallPost(_ io.Writer, _ *Options, _ *config.Instance, _ string) {}
