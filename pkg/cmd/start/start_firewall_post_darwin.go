//go:build darwin

package start

import (
	"fmt"
	"io"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/firewall"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/pkg/cmd/factory"
)

// setupPostBootFirewall installs the per-instance pfctl rule set after the VM
// boots. The VM IP is assigned by vmnet DHCP, so rules that scope by source
// address can only be written post-boot.
//
// Rules loaded:
//   - DNS redirect: VM traffic to any :53 → 127.0.0.1:<dnsPort>
//   - Allow DHCP, HTTP proxy on gateway, and ICMP to gateway
//   - Block everything else from the VM (default deny, matching libvirt nwfilter)
func setupPostBootFirewall(w io.Writer, f *factory.Factory, inst *config.Instance, name string, vmIP string) error {
	if vmIP == "" {
		logging.Warn("VM IP not available — traffic filter will not be active until VM gets an IP", "instance", name)
		return nil
	}

	client, err := f.PrivilegeClientFor(name)
	if err != nil {
		return fmt.Errorf("failed to get privilege client: %w", err)
	}

	pfctl := firewall.NewPfctlClient(client)

	fmt.Fprintln(w, "Setting up traffic filter...")
	if err := pfctl.EnsureEnabled(); err != nil {
		return fmt.Errorf("failed to enable PF firewall: %w", err)
	}

	if err := pfctl.ApplyInstanceRules(name, vmIP, inst.Gateway, inst.DNS.Port, inst.HTTP.Port); err != nil {
		return fmt.Errorf("failed to apply traffic filter: %w", err)
	}

	return nil
}
