//go:build darwin

package start

import (
	"fmt"
	"io"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/firewall"
	"github.com/sandialabs/abox/internal/privilege"
	"github.com/sandialabs/abox/pkg/cmd/factory"
)

// setupHostFirewall enables PF and ensures /etc/pf.conf references the
// abox/* anchors. Runs before the VM boots so that any one-time
// `pfctl -f /etc/pf.conf` reload happens before vmnet has installed the
// per-VM dynamic rules it adds at runtime — reloading the main ruleset
// after vmnet has populated those rules would clobber them, leaving the VM
// unreachable until the next vmnet bring-up.
//
// Per-instance rules (rdr, pass, block) require the VM IP and are applied
// in setupPostBootFirewall once vmnet has handed out a DHCP lease.
func setupHostFirewall(w io.Writer, f *factory.Factory, _ *config.Instance, name string) error {
	client, err := f.PrivilegeClientFor(name)
	if err != nil {
		return fmt.Errorf("failed to get privilege client: %w", err)
	}

	pfctl := firewall.NewPfctlClient(client)

	// pf.conf is mode 0644 by default, so we can read it without privilege.
	// Probe before/after EnsureEnabled so we can surface a user-visible
	// notice when the helper had to wire abox anchor references in. The
	// helper's own stderr is captured to a per-instance log file by
	// PrivilegeClientFor, so messaging it emits never reaches the terminal.
	wiredBefore, _ := privilege.HasAnchorReferences(privilege.PfconfDefaultPath)

	if err := pfctl.EnsureEnabled(); err != nil {
		return fmt.Errorf("failed to enable PF firewall: %w", err)
	}

	if !wiredBefore {
		if wiredAfter, _ := privilege.HasAnchorReferences(privilege.PfconfDefaultPath); wiredAfter {
			fmt.Fprintf(w, "Wired abox PF anchor references into %s.\n", privilege.PfconfDefaultPath)
		}
	}

	return nil
}
