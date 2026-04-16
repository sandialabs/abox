//go:build darwin

package remove

import (
	"io"

	"github.com/sandialabs/abox/internal/config"
)

// cleanupFirewallRules is a no-op on macOS.
// Phase 6 will add pfctl cleanup here.
func cleanupFirewallRules(_ io.Writer, _ *Options, _ *config.Instance, _ string) {}
