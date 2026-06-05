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
// PF itself and the /etc/pf.conf anchor wiring are handled pre-boot in
// setupHostFirewall; this function only writes the per-instance sub-anchor
// (abox/<name>), which doesn't reload the main ruleset and is therefore safe
// after vmnet has installed its runtime rules.
//
// Rules loaded:
//   - DNS redirect: VM traffic to any :53 → 127.0.0.1:<dnsPort>
//   - IPv6 block scoped to the VM's bridge (vmnet has no NAT66 off switch)
//   - Allow DHCP, HTTP proxy on gateway, and ICMP to gateway
//   - Block everything else from the VM (default deny, matching libvirt nwfilter)
func setupPostBootFirewall(w io.Writer, f *factory.Factory, _ *config.Instance, name string, vmIP string) error {
	if vmIP == "" {
		logging.Warn("VM IP not available — traffic filter will not be active until VM gets an IP", "instance", name)
		return nil
	}

	// Reload from disk: VMManager.Start persists the resolved bridge interface
	// into BackendConfig on its own copy of the config, so the caller's
	// in-memory instance predates it. The on-disk config also carries the
	// dnsfilter/httpfilter ports saved earlier in the start flow.
	inst, _, err := config.Load(name)
	if err != nil {
		return fmt.Errorf("failed to reload instance config: %w", err)
	}

	bridge := backendBridge(inst)
	if bridge == "" {
		return fmt.Errorf("bridge interface not recorded for instance %q; cannot scope IPv6 block", name)
	}

	client, err := f.PrivilegeClientFor(name)
	if err != nil {
		return fmt.Errorf("failed to get privilege client: %w", err)
	}

	pfctl := firewall.NewPfctlClient(client)

	fmt.Fprintln(w, "Setting up traffic filter...")
	if err := pfctl.ApplyInstanceRules(name, vmIP, inst.Gateway, bridge, inst.DNS.Port, inst.HTTP.Port); err != nil {
		return fmt.Errorf("failed to apply traffic filter: %w", err)
	}

	return nil
}

// backendBridge extracts the resolved vmnet bridge interface name that
// VMManager.Start persisted into the instance's BackendConfig.
func backendBridge(inst *config.Instance) string {
	if inst.BackendConfig == nil {
		return ""
	}
	v, ok := inst.BackendConfig["bridge"]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}
