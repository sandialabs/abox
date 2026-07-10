//go:build darwin

package vfkit

import (
	"fmt"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
)

// Host-mode deterministic per-VM /24 pool. vmnet-helper runs in host mode
// (no NAT), so abox owns subnet allocation: each instance gets its own /24
// from 192.168.128.0/24, .129.0/24, … The pool deliberately starts at .128 to
// avoid overlap with vmnet shared mode's 192.168.64.x pool used by Docker
// Desktop / OrbStack / Podman Machine.
const (
	hostSubnetPrefix   = "192.168"
	hostSubnetThirdMin = 128
	hostSubnetThirdMax = 254
)

// allocateHostSubnet picks the next free /24 from the host-mode pool, skipping
// subnets already claimed by existing abox instances. Returns the gateway (.1)
// and the subnet CIDR. On pool exhaustion or an instance-listing error it
// falls back to the base subnet; the gateway-reconciliation guard in
// VMManager.Start then surfaces any real conflict at boot time.
func allocateHostSubnet() (gateway, subnet string) {
	used := usedHostSubnets()
	for third := hostSubnetThirdMin; third <= hostSubnetThirdMax; third++ {
		candidate := fmt.Sprintf("%s.%d.0/24", hostSubnetPrefix, third)
		if !used[candidate] {
			return fmt.Sprintf("%s.%d.1", hostSubnetPrefix, third), candidate
		}
	}

	logging.Warn("host-mode subnet pool exhausted; falling back to base subnet",
		"base", fmt.Sprintf("%s.%d.0/24", hostSubnetPrefix, hostSubnetThirdMin))
	return fmt.Sprintf("%s.%d.1", hostSubnetPrefix, hostSubnetThirdMin),
		fmt.Sprintf("%s.%d.0/24", hostSubnetPrefix, hostSubnetThirdMin)
}

// usedHostSubnets returns the set of subnet CIDRs already claimed by existing
// instances, so allocation can skip them.
func usedHostSubnets() map[string]bool {
	used := make(map[string]bool)
	names, err := config.List()
	if err != nil {
		logging.Warn("failed to list instances for subnet allocation", "error", err)
		return used
	}
	for _, name := range names {
		inst, _, err := config.Load(name)
		if err != nil {
			logging.Warn("skipping unreadable instance config during subnet allocation",
				"instance", name, "error", err)
			continue
		}
		if inst.Subnet != "" {
			used[inst.Subnet] = true
		}
	}
	return used
}
