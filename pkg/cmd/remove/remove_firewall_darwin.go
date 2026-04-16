//go:build darwin

package remove

import (
	"io"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/firewall"
)

// cleanupFirewallRules removes pfctl rules for the instance during removal.
func cleanupFirewallRules(_ io.Writer, opts *Options, _ *config.Instance, name string) {
	if client, err := opts.Factory.PrivilegeClientFor(name); err == nil {
		firewall.NewPfctlClient(client).Flush(name)
	}
}
