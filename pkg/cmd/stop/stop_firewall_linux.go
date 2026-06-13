//go:build linux

package stop

import (
	"fmt"
	"io"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/firewall"
)

// cleanupFirewallPre removes iptables DNS redirect rules.
// Runs before daemon shutdown to match the original cleanup ordering.
func cleanupFirewallPre(w io.Writer, opts *Options, inst *config.Instance, name string) {
	// Remove iptables DNS redirect rules (flush all rules for this bridge).
	// Privilege is acquired lazily (best-effort) so stop succeeds even
	// without sudo — the VM shuts down regardless and firewall rules
	// become inert.
	if opts.Factory != nil {
		if client, err := opts.Factory.PrivilegeClientFor(name); err == nil {
			fmt.Fprintln(w, "Removing DNS redirect rules...")
			firewall.NewIPTablesClient(client).Flush(inst.Bridge)
		}
	}
}

// cleanupFirewallPost removes UFW rules.
// Runs after daemon shutdown to match the original cleanup ordering.
func cleanupFirewallPost(w io.Writer, opts *Options, inst *config.Instance, name string) {
	if opts.Factory != nil {
		if client, err := opts.Factory.PrivilegeClientFor(name); err == nil {
			firewall.NewUFWClient(client).Cleanup(w, inst.Bridge, "")
		}
	}
}
