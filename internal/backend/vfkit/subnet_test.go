//go:build darwin

package vfkit

import (
	"net"
	"os"
	"strconv"
	"testing"

	"github.com/sandialabs/abox/internal/config"
)

// writeInstanceConfig writes a minimal but valid instance config.yaml under the
// pinned XDG_DATA_HOME so config.List/Load (used by usedHostSubnets) see it.
func writeInstanceConfig(t *testing.T, name, subnet string) {
	t.Helper()
	paths, err := config.GetPaths(name)
	if err != nil {
		t.Fatalf("GetPaths(%q): %v", name, err)
	}
	if err := os.MkdirAll(paths.Instance, 0o755); err != nil {
		t.Fatalf("mkdir instance dir: %v", err)
	}
	inst := &config.Instance{
		Version: config.CurrentInstanceVersion,
		Name:    name,
		CPUs:    2,
		Memory:  2048,
		Disk:    "10G",
		Subnet:  subnet,
	}
	if err := config.Save(inst, paths); err != nil {
		t.Fatalf("save instance %q: %v", name, err)
	}
}

// pinDataHome points config storage at a fresh temp dir for the test.
func pinDataHome(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
}

func TestAllocateHostSubnet_Deterministic(t *testing.T) {
	pinDataHome(t)
	// With no instances, allocation should be deterministic across calls and
	// land on the base of the host-mode pool.
	gw1, sub1 := allocateHostSubnet()
	gw2, sub2 := allocateHostSubnet()
	if gw1 != gw2 || sub1 != sub2 {
		t.Errorf("allocation not deterministic: (%s,%s) vs (%s,%s)", gw1, sub1, gw2, sub2)
	}
	if sub1 != "192.168.128.0/24" || gw1 != "192.168.128.1" {
		t.Errorf("first allocation = (%s,%s), want (192.168.128.1, 192.168.128.0/24)", gw1, sub1)
	}
}

func TestAllocateHostSubnet_SkipsUsed(t *testing.T) {
	pinDataHome(t)
	// .128 and .129 already taken → allocator must skip to .130.
	writeInstanceConfig(t, "a", "192.168.128.0/24")
	writeInstanceConfig(t, "b", "192.168.129.0/24")

	gw, sub := allocateHostSubnet()
	if sub != "192.168.130.0/24" || gw != "192.168.130.1" {
		t.Errorf("allocation = (%s,%s), want (192.168.130.1, 192.168.130.0/24)", gw, sub)
	}
}

func TestAllocateHostSubnet_SkipsGap(t *testing.T) {
	pinDataHome(t)
	// A non-contiguous gap: .128 used but .129 free → allocator takes .129.
	writeInstanceConfig(t, "a", "192.168.128.0/24")

	_, sub := allocateHostSubnet()
	if sub != "192.168.129.0/24" {
		t.Errorf("allocation = %s, want 192.168.129.0/24", sub)
	}
}

func TestAllocateHostSubnet_NonOverlap(t *testing.T) {
	pinDataHome(t)
	// Distinct existing instances must never get the same subnet back, and a
	// new allocation must not overlap any of them.
	used := map[string]bool{}
	for _, third := range []int{128, 129, 130, 131} {
		sub := "192.168." + strconv.Itoa(third) + ".0/24"
		writeInstanceConfig(t, "i"+strconv.Itoa(third), sub)
		used[sub] = true
	}

	_, sub := allocateHostSubnet()
	if used[sub] {
		t.Fatalf("allocator returned an already-used subnet %s", sub)
	}
	if sub != "192.168.132.0/24" {
		t.Errorf("allocation = %s, want 192.168.132.0/24", sub)
	}
	// Confirm CIDR validity and non-overlap with each used subnet.
	_, newNet, err := net.ParseCIDR(sub)
	if err != nil {
		t.Fatalf("parse new subnet: %v", err)
	}
	for u := range used {
		_, uNet, _ := net.ParseCIDR(u)
		if newNet.Contains(uNet.IP) || uNet.Contains(newNet.IP) {
			t.Errorf("new subnet %s overlaps used %s", sub, u)
		}
	}
}

func TestAllocateHostSubnet_WithinPool(t *testing.T) {
	pinDataHome(t)
	// Whatever is allocated must stay within the locked host-mode pool:
	// 192.168.{128..254}.0/24.
	_, sub := allocateHostSubnet()
	ip, _, err := net.ParseCIDR(sub)
	if err != nil {
		t.Fatalf("parse subnet: %v", err)
	}
	v4 := ip.To4()
	if v4 == nil {
		t.Fatalf("subnet %s is not IPv4", sub)
	}
	if v4[0] != 192 || v4[1] != 168 {
		t.Errorf("subnet %s outside 192.168/16", sub)
	}
	if int(v4[2]) < hostSubnetThirdMin || int(v4[2]) > hostSubnetThirdMax {
		t.Errorf("subnet %s third octet %d outside pool [%d,%d]",
			sub, v4[2], hostSubnetThirdMin, hostSubnetThirdMax)
	}
}

func TestAllocateHostSubnet_Exhaustion(t *testing.T) {
	pinDataHome(t)
	// Fill the entire pool .128..254, then allocation must fall back to the
	// base subnet (the documented exhaustion behavior) rather than returning
	// an out-of-pool or empty value.
	for third := hostSubnetThirdMin; third <= hostSubnetThirdMax; third++ {
		sub := "192.168." + strconv.Itoa(third) + ".0/24"
		writeInstanceConfig(t, "x"+strconv.Itoa(third), sub)
	}

	gw, sub := allocateHostSubnet()
	if sub != "192.168.128.0/24" || gw != "192.168.128.1" {
		t.Errorf("exhaustion fallback = (%s,%s), want (192.168.128.1, 192.168.128.0/24)", gw, sub)
	}
}

func TestUsedHostSubnets_SkipsBlankSubnet(t *testing.T) {
	pinDataHome(t)
	// An instance with no subnet recorded must not pollute the used set.
	writeInstanceConfig(t, "withsub", "192.168.128.0/24")
	writeInstanceConfig(t, "nosub", "")

	used := usedHostSubnets()
	if !used["192.168.128.0/24"] {
		t.Error("expected the recorded subnet to be in the used set")
	}
	if len(used) != 1 {
		t.Errorf("used set = %v, want exactly the one non-empty subnet", used)
	}
}
