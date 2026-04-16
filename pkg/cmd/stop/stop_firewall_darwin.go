//go:build darwin

package stop

import (
	"fmt"
	"io"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/firewall"
)

// cleanupFirewallPre removes pfctl DNS redirect rules before daemon shutdown.
func cleanupFirewallPre(w io.Writer, opts *Options, _ *config.Instance, name string) {
	if opts.Factory != nil {
		if client, err := opts.Factory.PrivilegeClientFor(name); err == nil {
			fmt.Fprintln(w, "Removing DNS redirect rules...")
			firewall.NewPfctlClient(client).Flush(name)
		}
	}
}

// cleanupFirewallPost is a no-op on macOS — no UFW equivalent to clean up.
func cleanupFirewallPost(_ io.Writer, _ *Options, _ *config.Instance, _ string) {}
