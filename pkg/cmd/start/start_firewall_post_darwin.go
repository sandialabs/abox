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

// setupPostBootFirewall sets up pfctl DNS redirect rules after the VM boots.
// On macOS, we need the VM's IP address (assigned by vmnet DHCP) to create
// targeted PF rules — this is why setup happens post-boot rather than pre-boot.
func setupPostBootFirewall(w io.Writer, f *factory.Factory, inst *config.Instance, name string, vmIP string) error {
	if vmIP == "" {
		logging.Warn("VM IP not available — DNS filtering will not be active until VM gets an IP", "instance", name)
		return nil
	}

	client, err := f.PrivilegeClientFor(name)
	if err != nil {
		return fmt.Errorf("failed to get privilege client: %w", err)
	}

	pfctl := firewall.NewPfctlClient(client)

	fmt.Fprintln(w, "Setting up DNS redirect...")
	if err := pfctl.EnsureEnabled(); err != nil {
		return fmt.Errorf("failed to enable PF firewall: %w", err)
	}

	if err := pfctl.AddDNSRedirect(name, vmIP, inst.DNS.Port); err != nil {
		return fmt.Errorf("failed to add DNS redirect: %w", err)
	}

	return nil
}
