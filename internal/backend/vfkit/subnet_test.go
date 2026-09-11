//go:build darwin

package vfkit

import (
	"fmt"
	"testing"
)

func cidr(third int) string { return fmt.Sprintf("%s.%d.0/24", hostSubnetPrefix, third) }
func gw(third int) string   { return fmt.Sprintf("%s.%d.1", hostSubnetPrefix, third) }

// usedSet builds a used-subnet set covering the /24s at the given third octets.
func usedSet(thirds ...int) map[string]bool {
	m := make(map[string]bool, len(thirds))
	for _, t := range thirds {
		m[cidr(t)] = true
	}
	return m
}

// noConflict is a route-conflict predicate that never reports a conflict, i.e.
// the host routes none of the candidate subnets. Used by tests that exercise only
// the used-set logic.
func noConflict(string) bool { return false }

func TestPickHostSubnet_DeterministicFirst(t *testing.T) {
	gateway, subnet, err := pickHostSubnet(nil, noConflict)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gateway != gw(hostSubnetThirdMin) || subnet != cidr(hostSubnetThirdMin) {
		t.Fatalf("first allocation = (%s, %s), want (%s, %s)",
			gateway, subnet, gw(hostSubnetThirdMin), cidr(hostSubnetThirdMin))
	}
}

func TestPickHostSubnet_SkipsUsed(t *testing.T) {
	// First two subnets taken -> allocator should return the third.
	used := usedSet(hostSubnetThirdMin, hostSubnetThirdMin+1)
	gateway, subnet, err := pickHostSubnet(used, noConflict)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantThird := hostSubnetThirdMin + 2
	if gateway != gw(wantThird) || subnet != cidr(wantThird) {
		t.Fatalf("allocation = (%s, %s), want (%s, %s)",
			gateway, subnet, gw(wantThird), cidr(wantThird))
	}
}

func TestPickHostSubnet_SkipsRouteConflict(t *testing.T) {
	// The host already routes the first candidate's gateway (e.g. a VPN owns
	// 192.168.128.0/24); allocation must advance to the next unrouted /24.
	firstGW := gw(hostSubnetThirdMin)
	conflicts := func(gwIP string) bool { return gwIP == firstGW }

	gateway, subnet, err := pickHostSubnet(nil, conflicts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantThird := hostSubnetThirdMin + 1
	if gateway != gw(wantThird) || subnet != cidr(wantThird) {
		t.Fatalf("allocation = (%s, %s), want (%s, %s)",
			gateway, subnet, gw(wantThird), cidr(wantThird))
	}
}

func TestPickHostSubnet_NonOverlapping(t *testing.T) {
	// Simulate sequential allocation: each result is added to the used set.
	used := map[string]bool{}
	seen := map[string]bool{}
	for i := range 5 {
		_, subnet, err := pickHostSubnet(used, noConflict)
		if err != nil {
			t.Fatalf("allocation %d: unexpected error: %v", i, err)
		}
		if seen[subnet] {
			t.Fatalf("allocation %d reused subnet %s", i, subnet)
		}
		seen[subnet] = true
		used[subnet] = true
	}
}

func TestPickHostSubnet_ExhaustionErrors(t *testing.T) {
	// Mark the entire pool as used; allocator must return an error rather than a
	// colliding fallback subnet (subnet-keyed pf rules make collisions unsafe).
	used := map[string]bool{}
	for third := hostSubnetThirdMin; third <= hostSubnetThirdMax; third++ {
		used[cidr(third)] = true
	}
	if _, _, err := pickHostSubnet(used, noConflict); err == nil {
		t.Fatal("expected an error on pool exhaustion, got nil")
	}
}
