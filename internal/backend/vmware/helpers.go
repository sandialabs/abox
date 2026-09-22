package vmware

import (
	"fmt"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/vmrun"
)

// vnetFor resolves the enforcement interface for an instance: the allocated vmnet
// recorded in inst.BackendConfig["vnet"] by the NetworkManager. This is the real
// host interface the egress enforcer must reference (iptables on Linux/Windows, pf
// on macOS), so it is what we pass to the enforcer/rule builder as the "bridge".
// An empty value means the network was never created, which is a hard error for
// any enforcement operation. Shared by the darwin (pf) and non-darwin (iptables)
// egress controllers — the resolution is platform-independent.
func vnetFor(inst *config.Instance) (string, error) {
	if s, ok := inst.BackendString(vmrun.VNetConfigKey); ok && s != "" {
		return s, nil
	}
	return "", fmt.Errorf("no vmnet allocated for instance %q (network not created); cannot enforce egress", inst.Name)
}
