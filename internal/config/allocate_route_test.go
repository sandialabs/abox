package config

import (
	"net"
	"os"
	"testing"
)

// TestAllocateSubnet_DefaultProbeNoop confirms that with the default (no-op)
// route probe, AllocateSubnet does not consult the host routing table and returns
// the first free candidate. This guards test hermeticity: unit tests must never
// shell out to ip/route, which holds only while routeProbe defaults to a no-op.
func TestAllocateSubnet_DefaultProbeNoop(t *testing.T) {
	mock := NewMockFileSystem()
	mock.ReadDirErr = os.ErrNotExist // empty instance store -> deterministic
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	subnet, gateway, third, err := AllocateSubnet("10.10.0.0/16")
	if err != nil {
		t.Fatalf("AllocateSubnet error = %v", err)
	}
	if subnet != "10.10.10.0/24" || gateway != "10.10.10.1" || third != 10 {
		t.Fatalf("AllocateSubnet = (%s, %s, %d), want (10.10.10.0/24, 10.10.10.1, 10)", subnet, gateway, third)
	}
}

// TestAllocateSubnet_SkipsRouteConflict verifies that an installed route prober
// makes AllocateSubnet skip a /24 the host already routes elsewhere.
func TestAllocateSubnet_SkipsRouteConflict(t *testing.T) {
	mock := NewMockFileSystem()
	mock.ReadDirErr = os.ErrNotExist
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	orig := routeProbe
	t.Cleanup(func() { routeProbe = orig })
	// Host routes the first candidate's gateway; allocation must advance to .11.
	SetRouteProbe(func(gw string) bool { return gw == "10.10.10.1" })

	subnet, gateway, third, err := AllocateSubnet("10.10.0.0/16")
	if err != nil {
		t.Fatalf("AllocateSubnet error = %v", err)
	}
	if subnet != "10.10.11.0/24" || gateway != "10.10.11.1" || third != 11 {
		t.Fatalf("AllocateSubnet = (%s, %s, %d), want the next /24 (10.10.11.0/24, 10.10.11.1, 11)", subnet, gateway, third)
	}
}

// TestAllocateSubnet_SkipsDefinedNetworkSubnet verifies that a /24 claimed by a
// network DEFINED on the shared host backend (including another user's stopped
// network, which the route probe can't see) is skipped — the cross-user
// double-book fix.
func TestAllocateSubnet_SkipsDefinedNetworkSubnet(t *testing.T) {
	mock := NewMockFileSystem()
	mock.ReadDirErr = os.ErrNotExist
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	orig := definedSubnetsProbe
	t.Cleanup(func() { definedSubnetsProbe = orig })
	// A defined-but-stopped network already claims the first candidate /24.
	SetDefinedSubnetsProbe(func() []*net.IPNet { return []*net.IPNet{mustCIDR(t, "10.10.10.0/24")} })

	subnet, gateway, third, err := AllocateSubnet("10.10.0.0/16")
	if err != nil {
		t.Fatalf("AllocateSubnet error = %v", err)
	}
	if subnet != "10.10.11.0/24" || gateway != "10.10.11.1" || third != 11 {
		t.Fatalf("AllocateSubnet = (%s, %s, %d), want the next /24 (10.10.11.0/24, 10.10.11.1, 11)", subnet, gateway, third)
	}
}

// TestAllocateSubnet_SkipsWiderDefinedNetwork verifies containment semantics: a
// defined network WIDER than a /24 (e.g. a /16 covering the whole default pool
// prefix range up to a point) blocks every candidate inside it, which a
// string-equality check on the CIDR would miss.
func TestAllocateSubnet_SkipsWiderDefinedNetwork(t *testing.T) {
	mock := NewMockFileSystem()
	mock.ReadDirErr = os.ErrNotExist
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	orig := definedSubnetsProbe
	t.Cleanup(func() { definedSubnetsProbe = orig })
	// A /22 covers 10.10.8.0-10.10.11.255, i.e. candidates .10 and .11.
	SetDefinedSubnetsProbe(func() []*net.IPNet { return []*net.IPNet{mustCIDR(t, "10.10.8.0/22")} })

	subnet, _, third, err := AllocateSubnet("10.10.0.0/16")
	if err != nil {
		t.Fatalf("AllocateSubnet error = %v", err)
	}
	if subnet != "10.10.12.0/24" || third != 12 {
		t.Fatalf("AllocateSubnet = (%s, %d), want the first /24 outside the /22 (10.10.12.0/24, 12)", subnet, third)
	}
}

// TestAllocateSubnet_SkipsNarrowerDefinedNetwork verifies the other containment
// direction: a defined network NARROWER than a /24 (whose base the candidate's
// gateway doesn't fall inside) still blocks the covering /24 candidate.
func TestAllocateSubnet_SkipsNarrowerDefinedNetwork(t *testing.T) {
	mock := NewMockFileSystem()
	mock.ReadDirErr = os.ErrNotExist
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	orig := definedSubnetsProbe
	t.Cleanup(func() { definedSubnetsProbe = orig })
	// A /25 in the upper half of 10.10.10.0/24: does not contain the .1 gateway,
	// so only candidate-contains-network catches it.
	SetDefinedSubnetsProbe(func() []*net.IPNet { return []*net.IPNet{mustCIDR(t, "10.10.10.128/25")} })

	subnet, _, third, err := AllocateSubnet("10.10.0.0/16")
	if err != nil {
		t.Fatalf("AllocateSubnet error = %v", err)
	}
	if subnet != "10.10.11.0/24" || third != 11 {
		t.Fatalf("AllocateSubnet = (%s, %d), want the next /24 (10.10.11.0/24, 11)", subnet, third)
	}
}

// TestAllocateSubnet_DefaultDefinedProbeNoop confirms the defined-subnets probe
// defaults to a no-op so unit tests never shell out to virsh (hermeticity, like
// the route probe above).
func TestAllocateSubnet_DefaultDefinedProbeNoop(t *testing.T) {
	mock := NewMockFileSystem()
	mock.ReadDirErr = os.ErrNotExist
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	subnet, _, _, err := AllocateSubnet("10.10.0.0/16")
	if err != nil {
		t.Fatalf("AllocateSubnet error = %v", err)
	}
	if subnet != "10.10.10.0/24" {
		t.Fatalf("AllocateSubnet = %s, want first candidate 10.10.10.0/24 with no-op defined probe", subnet)
	}
}

func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	return n
}
