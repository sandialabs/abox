//go:build linux

package remove

import (
	"io"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/firewall"
)

// cleanupFirewallRules removes UFW rules for the instance's bridge interface.
func cleanupFirewallRules(w io.Writer, opts *Options, inst *config.Instance, name string) {
	if client, err := opts.Factory.PrivilegeClientFor(name); err == nil {
		firewall.NewUFWClient(client).Cleanup(w, inst.Bridge, "  ")
	}
}
