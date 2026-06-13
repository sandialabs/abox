package backend

import (
	"fmt"

	"github.com/sandialabs/abox/internal/config"
)

// ResolveNetwork determines the subnet, gateway, and VM IP address for an
// instance. Backends that manage their own networking (e.g. vfkit/vmnet host
// mode on macOS, via the SubnetProvider interface) own subnet allocation, so
// their NetworkDefaults are used instead of the default abox subnet pool.
//
// This is the single source of truth shared by `abox create` and `abox import`
// so the two flows cannot drift: an imported macOS instance must land in the
// backend's deterministic host-mode pool (192.168.128+), never the Linux
// 10.10.0.0/16 pool.
//
// If userSubnet is non-empty it is validated and used verbatim (gateway is
// derived from it). Otherwise, if the backend implements SubnetProvider its
// managed network is used; failing that, a subnet is allocated from the default
// pool.
func ResolveNetwork(be Backend, userSubnet string) (subnet, gateway, ipAddress string, err error) {
	if userSubnet != "" {
		gw, _, verr := config.ValidateSubnet(userSubnet)
		if verr != nil {
			return "", "", "", fmt.Errorf("invalid subnet: %w", verr)
		}
		return userSubnet, gw, DeriveIPAddress(gw), nil
	}

	if sp, ok := be.(SubnetProvider); ok {
		gw, sn := sp.NetworkDefaults()
		return sn, gw, DeriveIPAddress(gw), nil
	}

	sn, gw, _, aerr := config.AllocateSubnet("")
	if aerr != nil {
		return "", "", "", fmt.Errorf("failed to allocate subnet: %w", aerr)
	}
	return sn, gw, DeriveIPAddress(gw), nil
}

// DeriveIPAddress derives the VM IP address from the gateway address.
// Gateway "10.10.20.1" becomes VM IP "10.10.20.10".
func DeriveIPAddress(gateway string) string {
	var a, b, c int
	_, _ = fmt.Sscanf(gateway, "%d.%d.%d", &a, &b, &c)
	return fmt.Sprintf("%d.%d.%d.10", a, b, c)
}
