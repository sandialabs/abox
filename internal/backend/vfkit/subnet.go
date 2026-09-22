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
// subnets already claimed by existing abox instances and subnets the host already
// routes elsewhere (e.g. a VPN split-include route that would make the guest
// unreachable from the host). Returns the gateway (.1) and the subnet CIDR, or an
// error when the pool is exhausted.
func allocateHostSubnet() (gateway, subnet string, err error) {
	return pickHostSubnet(usedHostSubnets(), config.RouteConflicts)
}

// pickHostSubnet is the pure allocation logic behind allocateHostSubnet: it
// selects the next free /24 from the host-mode pool given the set of already-used
// subnet CIDRs and a conflicts predicate that reports whether the host already
// routes a candidate's gateway. Factored out (with conflicts injected) so it can
// be tested without touching the instance store or the host routing table.
//
// On exhaustion it returns an error rather than a colliding fallback: because pf
// rules key on the subnet, handing out an in-use /24 would let two instances
// share one anchor policy (cross-wired DNS redirects). An error is the safe,
// honest outcome — the operator removes an instance to free a subnet.
func pickHostSubnet(used map[string]bool, conflicts func(gatewayIP string) bool) (gateway, subnet string, err error) {
	for third := hostSubnetThirdMin; third <= hostSubnetThirdMax; third++ {
		candidate := fmt.Sprintf("%s.%d.0/24", hostSubnetPrefix, third)
		gw := fmt.Sprintf("%s.%d.1", hostSubnetPrefix, third)
		// used[] first so a claimed subnet costs zero route probes.
		if !used[candidate] && !conflicts(gw) {
			return gw, candidate, nil
		}
	}

	return "", "", fmt.Errorf(
		"host-mode subnet pool exhausted: all /24s from %s.%d.0/24 to %s.%d.0/24 are in use; remove an instance to free a subnet",
		hostSubnetPrefix, hostSubnetThirdMin, hostSubnetPrefix, hostSubnetThirdMax)
}

// usedHostSubnets returns the set of subnet CIDRs already claimed by existing
// instances, so allocation can skip them. It delegates the instance scan to the
// shared config.UsedInstanceSubnets and, unlike the default allocator, treats an
// enumeration failure as non-fatal: it warns and returns an empty set so
// allocation falls back to the base subnet (the gateway-reconciliation guard in
// VMManager.Start surfaces any real conflict at boot time).
func usedHostSubnets() map[string]bool {
	used, err := config.UsedInstanceSubnets()
	if err != nil {
		logging.Warn("failed to list instances for subnet allocation", "error", err)
		return map[string]bool{}
	}
	return used
}
