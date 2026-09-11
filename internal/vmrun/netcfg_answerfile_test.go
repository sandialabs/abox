//go:build linux || darwin

package vmrun

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestApplyHostOnlyDirectives_PreservesOtherVNets verifies the answer-file
// transform writes exactly this VNET's host-only lines and leaves every other
// VNET (notably the default NAT VNET_8) untouched.
func TestApplyHostOnlyDirectives_PreservesOtherVNets(t *testing.T) {
	existing := strings.Join([]string{
		"VERSION=1,0",
		"answer VNET_1_HOSTONLY_SUBNET 192.168.1.0",
		"answer VNET_8_NAT yes",
		"answer VNET_8_DHCP yes",
	}, "\n") + "\n"

	cfg := HostOnlyConfig{VNet: "vmnet2", Subnet: "10.10.10.0", Gateway: "10.10.10.1", Netmask: "255.255.255.0"}
	got, err := applyHostOnlyDirectives(existing, cfg)
	if err != nil {
		t.Fatalf("applyHostOnlyDirectives: %v", err)
	}

	// Other VNETs preserved verbatim.
	for _, must := range []string{"VERSION=1,0", "answer VNET_1_HOSTONLY_SUBNET 192.168.1.0", "answer VNET_8_NAT yes", "answer VNET_8_DHCP yes"} {
		if !strings.Contains(got, must) {
			t.Errorf("transform dropped a foreign line %q:\n%s", must, got)
		}
	}
	// This VNET's host-only set present. NAT is written explicitly as "no" (see
	// hostOnlyDirectives) rather than omitted.
	for _, must := range []string{
		"answer VNET_2_HOSTONLY_SUBNET 10.10.10.0",
		"answer VNET_2_HOSTONLY_NETMASK 255.255.255.0",
		"answer VNET_2_VIRTUAL_ADAPTER yes",
		"answer VNET_2_NAT no",
		"answer VNET_2_DHCP no",
	} {
		if !strings.Contains(got, must) {
			t.Errorf("missing host-only line %q:\n%s", must, got)
		}
	}
	// Never NAT-ENABLING or a bridge stanza for our VNET (an explicit "NAT no" is
	// the isolation guarantee; "NAT yes"/bridge would break it).
	if strings.Contains(got, "VNET_2_NAT yes") || strings.Contains(got, "VNET_2_BRIDGE") {
		t.Errorf("host-only apply emitted a NAT-enabling/bridge stanza for VNET_2:\n%s", got)
	}
}

// TestApplyHostOnlyDirectives_SeedsVersionHeader verifies that applying to an
// EMPTY networking file (a host whose file abox is creating from scratch) seeds
// the "VERSION=1,0" header as line 1, and does not duplicate it when one already
// exists.
func TestApplyHostOnlyDirectives_SeedsVersionHeader(t *testing.T) {
	cfg := HostOnlyConfig{VNet: "vmnet2", Subnet: "10.10.10.0", Gateway: "10.10.10.1", Netmask: "255.255.255.0"}

	got, err := applyHostOnlyDirectives("", cfg)
	if err != nil {
		t.Fatalf("applyHostOnlyDirectives(empty): %v", err)
	}
	if !strings.HasPrefix(got, "VERSION=1,0\n") {
		t.Errorf("fresh file must start with VERSION=1,0 header:\n%s", got)
	}
	if n := strings.Count(got, "VERSION="); n != 1 {
		t.Errorf("want exactly one VERSION line, got %d:\n%s", n, got)
	}

	// Re-applying a file that already has the header must not add a second one.
	again, err := applyHostOnlyDirectives(got, cfg)
	if err != nil {
		t.Fatalf("applyHostOnlyDirectives(again): %v", err)
	}
	if n := strings.Count(again, "VERSION="); n != 1 {
		t.Errorf("re-apply duplicated VERSION line, got %d:\n%s", n, again)
	}
}

// TestApplyHostOnlyDirectives_Idempotent verifies re-applying replaces (not
// duplicates) this VNET's lines, and that VNET_2 is not confused with VNET_20.
func TestApplyHostOnlyDirectives_Idempotent(t *testing.T) {
	cfg := HostOnlyConfig{VNet: "vmnet2", Subnet: "10.10.10.0", Gateway: "10.10.10.1", Netmask: "255.255.255.0"}
	first, err := applyHostOnlyDirectives("answer VNET_20_HOSTONLY_SUBNET 172.16.0.0\n", cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := applyHostOnlyDirectives(first, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("re-apply not idempotent:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	if strings.Count(second, "answer VNET_2_DHCP no") != 1 {
		t.Errorf("expected exactly one VNET_2_DHCP line, got:\n%s", second)
	}
	// VNET_20 (different number) must survive.
	if !strings.Contains(second, "answer VNET_20_HOSTONLY_SUBNET 172.16.0.0") {
		t.Errorf("VNET_20 line was wrongly dropped by VNET_2 edit:\n%s", second)
	}
}

// TestRemoveHostOnlyDirectives verifies removal drops only this VNET's lines and
// reports whether anything changed.
func TestRemoveHostOnlyDirectives(t *testing.T) {
	existing := strings.Join([]string{
		"answer VNET_2_HOSTONLY_SUBNET 10.10.10.0",
		"answer VNET_2_DHCP no",
		"answer VNET_8_NAT yes",
	}, "\n") + "\n"

	got, removed := removeHostOnlyDirectives(existing, "vmnet2")
	if !removed {
		t.Fatal("expected removed=true")
	}
	if strings.Contains(got, "VNET_2_") {
		t.Errorf("VNET_2 lines survived removal:\n%s", got)
	}
	if !strings.Contains(got, "answer VNET_8_NAT yes") {
		t.Errorf("removal disturbed VNET_8:\n%s", got)
	}

	// Removing an absent VNET is a no-op.
	if _, removed := removeHostOnlyDirectives(got, "vmnet5"); removed {
		t.Error("expected removed=false for an absent vmnet")
	}
}

// TestFileProvisioner_Configure exercises the Linux/Fusion path end-to-end against
// a temp answer-file and a faked tool: the file gains this VNET's host-only lines
// and the restart sequence runs through the seam.
func TestFileProvisioner_Configure(t *testing.T) {
	dir := t.TempDir()
	netPath := filepath.Join(dir, "networking")
	if err := os.WriteFile(netPath, []byte("VERSION=1,0\nanswer VNET_8_NAT yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer setLookPath(func(string) (string, error) { return "vmware-networks", nil })()

	var calls [][]string
	restore := SetRunCommandForTest(func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	})
	defer restore()

	p := fileProvisioner{
		networkingPath: netPath,
		toolCandidates: []string{"vmware-networks"},
		applyArgs:      [][]string{{"--stop"}, {"--start"}},
	}
	cfg := HostOnlyConfig{VNet: "vmnet2", Subnet: "10.10.10.0", Gateway: "10.10.10.1", Netmask: "255.255.255.0"}
	if err := p.configure(context.Background(), cfg); err != nil {
		t.Fatalf("configure: %v", err)
	}

	data, _ := os.ReadFile(netPath)
	content := string(data)
	if !strings.Contains(content, "answer VNET_2_VIRTUAL_ADAPTER yes") || !strings.Contains(content, "answer VNET_8_NAT yes") {
		t.Errorf("networking file missing expected lines:\n%s", content)
	}
	want := [][]string{{"vmware-networks", "--stop"}, {"vmware-networks", "--start"}}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("restart calls = %v, want %v", calls, want)
	}
}

// TestFileProvisioner_UnconfigureNoopWhenAbsent verifies teardown of a vmnet with
// no lines in the file does not run a restart (idempotent no-op).
func TestFileProvisioner_UnconfigureNoopWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	netPath := filepath.Join(dir, "networking")
	if err := os.WriteFile(netPath, []byte("VERSION=1,0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	called := false
	restore := SetRunCommandForTest(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		called = true
		return nil, nil
	})
	defer restore()

	p := fileProvisioner{networkingPath: netPath, toolCandidates: []string{"vmware-networks"}, applyArgs: [][]string{{"--stop"}}}
	if err := p.unconfigure(context.Background(), "vmnet7"); err != nil {
		t.Fatalf("unconfigure: %v", err)
	}
	if called {
		t.Error("restart tool was invoked for an absent vmnet; expected no-op")
	}
}

// TestFileProvisioner_GuardRejectsUplink verifies the uplink guard fires before
// any file write for a hostile vnet/config value.
func TestFileProvisioner_GuardRejectsUplink(t *testing.T) {
	p := fileProvisioner{networkingPath: filepath.Join(t.TempDir(), "networking"), toolCandidates: []string{"x"}, applyArgs: nil}
	err := p.unconfigure(context.Background(), "vmnet-nat")
	if !errors.Is(err, errUplinkForbidden) {
		t.Fatalf("unconfigure(vmnet-nat) err = %v, want errUplinkForbidden", err)
	}
}

// TestConfigure_GuardRejectsUplinkInConfig_File verifies the WRITE path
// (fileProvisioner.configure) rejects a config whose fields carry an uplink token
// BEFORE any file write.
func TestConfigure_GuardRejectsUplinkInConfig_File(t *testing.T) {
	// A hostile value in a config field (here the subnet) must trip the guard.
	badCfg := HostOnlyConfig{VNet: "vmnet2", Subnet: "nat", Gateway: "10.10.10.1", Netmask: "255.255.255.0"}

	netPath := filepath.Join(t.TempDir(), "networking")
	fp := fileProvisioner{networkingPath: netPath, toolCandidates: []string{"x"}, applyArgs: [][]string{{"--start"}}}
	if err := fp.configure(context.Background(), badCfg); !errors.Is(err, errUplinkForbidden) {
		t.Fatalf("fileProvisioner.configure err = %v, want errUplinkForbidden", err)
	}
	if _, err := os.Stat(netPath); !os.IsNotExist(err) {
		t.Errorf("networking file was written despite a rejected config: %v", err)
	}
}

// TestActiveProvisioner_Configures verifies the compile-time-selected provisioner
// on this unix host is the answer-file provisioner and edits a redirected file.
func TestActiveProvisioner_Configures(t *testing.T) {
	dir := t.TempDir()
	netPath := filepath.Join(dir, "networking")
	defer SetNetworkingPathForTest(netPath)()
	defer setLookPath(func(string) (string, error) { return "vmware-networks", nil })()
	defer SetRunCommandForTest(func(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, nil })()

	p, err := activeProvisioner()
	if err != nil {
		t.Fatalf("activeProvisioner: %v", err)
	}
	cfg := HostOnlyConfig{VNet: "vmnet2", Subnet: "10.10.10.0", Gateway: "10.10.10.1", Netmask: "255.255.255.0"}
	if err := p.configure(context.Background(), cfg); err != nil {
		t.Fatalf("configure via activeProvisioner: %v", err)
	}
	data, err := os.ReadFile(netPath)
	if err != nil {
		t.Fatalf("read redirected networking file: %v", err)
	}
	if !strings.Contains(string(data), "answer VNET_2_VIRTUAL_ADAPTER yes") {
		t.Errorf("activeProvisioner did not write host-only lines:\n%s", data)
	}
}
