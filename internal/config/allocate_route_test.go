package config

import (
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
