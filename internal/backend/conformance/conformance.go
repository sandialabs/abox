// Package conformance provides a shared, hermetic contract test suite that runs
// the SAME invariant assertions against every backend implementation.
//
// Each backend (libvirt, vmware, mock) is unit-tested in isolation with
// divergent, hand-written cases. Those isolated tests cannot catch the two
// backends silently DISAGREEING on the semantics of the shared
// backend.Backend interface. RunBackendContract asserts the pure-contract
// invariants — the ones that must hold identically for every backend and that
// do NOT require a live hypervisor, daemon, or shelling out to
// virsh/vmrun/qemu-img — so a future backend (or a regression in an existing
// one) is caught the moment it violates the contract.
//
// Everything here is HERMETIC: no Create/Start/Import, no privilege helper, no
// network, no filesystem beyond t.TempDir(). Contract points that cannot be
// checked without a live system are deliberately left to the per-backend unit
// tests and the e2e suite; those are called out in comments below.
package conformance

import (
	"bytes"
	"net"
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
)

// Expectations describes which OPTIONAL backend interfaces a given backend is
// contractually expected to implement. The optional interfaces are discovered
// two different ways in the codebase:
//
//   - Accessor methods on Backend that return nil when unsupported
//     (Snapshot, EgressController, MonitorTransport).
//   - Free-standing interfaces discovered by type assertion on the concrete
//     backend value (ToolRequirer, TemplateValidator, EgressProviderSetter,
//     StorageProviderSetter, NetworkDefaulter).
//
// RunBackendContract asserts BOTH styles are internally consistent: if a
// backend advertises support, the accessor/assertion yields a usable value; if
// it does not, the result is cleanly nil (no panic).
type Expectations struct {
	// Name is the value Backend.Name() must return.
	Name string

	// Snapshot / EgressController / MonitorTransport: whether the corresponding
	// accessor must return a non-nil value.
	Snapshot         bool
	EgressController bool
	MonitorTransport bool

	// ToolRequirer / TemplateValidator / EgressProviderSetter / StorageProviderSetter
	// / NetworkDefaulter: whether the concrete backend value must satisfy the
	// free-standing optional interface. StorageProviderSetter (libvirt) and
	// NetworkDefaulter (vfkit/vmware) are load-bearing in the factory
	// (injectStorageProvider / ResolveNetwork), so the contract asserts them too.
	ToolRequirer          bool
	TemplateValidator     bool
	EgressProviderSetter  bool
	StorageProviderSetter bool
	NetworkDefaulter      bool
}

// RunBackendContract runs every hermetic contract assertion against b, using
// exp to know which optional interfaces b is expected to implement. It is safe
// to call from any GOOS: it constructs no resources and shells out to nothing.
func RunBackendContract(t *testing.T, b backend.Backend, exp Expectations) {
	t.Helper()

	t.Run("Name", func(t *testing.T) { assertName(t, b, exp) })
	t.Run("GenerateMAC", func(t *testing.T) { assertGenerateMAC(t, b) })
	t.Run("ResourceNames", func(t *testing.T) { assertResourceNames(t, b) })
	t.Run("StorageDir", func(t *testing.T) { assertStorageDir(t, b) })
	t.Run("DryRun", func(t *testing.T) { assertDryRun(t, b) })
	t.Run("BuildEgressPolicy", func(t *testing.T) { assertBuildEgressPolicy(t) })
	t.Run("OptionalInterfaces", func(t *testing.T) { assertOptionalInterfaces(t, b, exp) })
}

func assertName(t *testing.T, b backend.Backend, exp Expectations) {
	t.Helper()
	if got := b.Name(); got != exp.Name {
		t.Errorf("Name() = %q, want %q", got, exp.Name)
	}
}

// assertGenerateMAC asserts GenerateMAC returns a syntactically valid,
// locally-administered / vendor-prefixed unicast MAC, and does so on every
// call. It does NOT assert uniqueness across calls (that is a randomness
// property, not a contract) — only that the FORMAT contract holds each time.
func assertGenerateMAC(t *testing.T, b backend.Backend) {
	t.Helper()
	for range 2 {
		mac := b.GenerateMAC()
		if mac == "" {
			t.Fatal("GenerateMAC() = empty string")
		}
		hw, err := net.ParseMAC(mac)
		if err != nil {
			t.Fatalf("GenerateMAC() = %q, not parseable: %v", mac, err)
		}
		if len(hw) != 6 {
			t.Errorf("GenerateMAC() = %q, want a 6-octet EUI-48, got %d octets", mac, len(hw))
		}
		// Must be a unicast address: the least-significant bit of the first
		// octet is the I/G bit; 1 means multicast, which is invalid for a NIC.
		if hw[0]&0x01 != 0 {
			t.Errorf("GenerateMAC() = %q is a multicast address (I/G bit set); NIC MACs must be unicast", mac)
		}
	}
}

// assertResourceNames asserts the cross-backend ResourceNames contract that
// holds for every backend: it is deterministic (same input -> same output), it
// echoes the instance name back in .Instance, and it yields non-empty VM and
// Network names. The exact naming convention differs per backend (real backends
// use the "abox-<name>" form, mock uses its own prefix), so that is left to each
// backend's own tests rather than asserted here.
func assertResourceNames(t *testing.T, b backend.Backend) {
	t.Helper()
	for _, name := range []string{"dev", "my-instance", "very-long-instance-name-for-testing"} {
		n1 := b.ResourceNames(name)
		n2 := b.ResourceNames(name)
		if n1 != n2 {
			t.Errorf("ResourceNames(%q) not deterministic: %+v != %+v", name, n1, n2)
		}
		if n1.Instance != name {
			t.Errorf("ResourceNames(%q).Instance = %q, want %q", name, n1.Instance, name)
		}
		if n1.VM == "" {
			t.Errorf("ResourceNames(%q).VM is empty", name)
		}
		if n1.Network == "" {
			t.Errorf("ResourceNames(%q).Network is empty", name)
		}
	}
}

func assertStorageDir(t *testing.T, b backend.Backend) {
	t.Helper()
	if b.StorageDir() == "" {
		t.Error("StorageDir() is empty; a backend must name a root for managed disk images")
	}
}

// assertDryRun asserts DryRun is a pure, read-only rendering: it must produce
// output and must not error for a well-formed instance, WITHOUT creating any
// resource. It uses AssumeCloudInitExists so no ISO file needs to exist on
// disk. The exact rendered content is backend-specific and is asserted by each
// backend's own tests; here we only assert the shared contract (no error, some
// bytes written).
func assertDryRun(t *testing.T, b backend.Backend) {
	t.Helper()
	inst := testInstance()
	// The real backends render a NIC from inst.MACAddress; supply one from the
	// backend's own generator so the (hermetic) rendering has a valid address.
	inst.MACAddress = b.GenerateMAC()
	paths := &config.Paths{Instance: t.TempDir()}
	var buf bytes.Buffer
	if err := b.DryRun(inst, paths, &buf, backend.VMCreateOptions{AssumeCloudInitExists: true}); err != nil {
		t.Fatalf("DryRun() error = %v", err)
	}
	if buf.Len() == 0 {
		t.Error("DryRun() wrote no output")
	}
}

// assertBuildEgressPolicy asserts the package-level BuildEgressPolicy is a pure
// function of the instance and maps the instance's DNS/HTTP ports onto the
// policy, with the standard guest-facing DNS port (53). This is backend-neutral
// (it lives in the backend package, not any implementation), so it maps
// identically for every backend given the same instance — that identity IS the
// cross-backend contract. It takes no backend because the function under test is
// backend-neutral; running it under each backend's subtest documents that the
// derived policy is shared, not per-backend.
func assertBuildEgressPolicy(t *testing.T) {
	t.Helper()
	inst := testInstance()
	p := backend.BuildEgressPolicy(inst)
	if p.DNSPort != inst.DNS.Port {
		t.Errorf("BuildEgressPolicy().DNSPort = %d, want %d", p.DNSPort, inst.DNS.Port)
	}
	if p.HTTPPort != inst.HTTP.Port {
		t.Errorf("BuildEgressPolicy().HTTPPort = %d, want %d", p.HTTPPort, inst.HTTP.Port)
	}
	if p.GuestDNSPort != 53 {
		t.Errorf("BuildEgressPolicy().GuestDNSPort = %d, want 53 (standard guest DNS port)", p.GuestDNSPort)
	}
	if p.Gateway != inst.Gateway {
		t.Errorf("BuildEgressPolicy().Gateway = %q, want %q", p.Gateway, inst.Gateway)
	}
}

// assertOptionalInterfaces asserts the optional-interface discovery is
// internally consistent with exp for both discovery styles.
func assertOptionalInterfaces(t *testing.T, b backend.Backend, exp Expectations) {
	t.Helper()

	// --- Accessor-style optionals (nil when unsupported) ---
	if exp.Snapshot {
		if b.Snapshot() == nil {
			t.Error("Snapshot() = nil, want non-nil (backend advertises snapshot support)")
		}
	}
	if exp.EgressController {
		if b.EgressController() == nil {
			t.Error("EgressController() = nil, want non-nil (backend advertises egress control)")
		}
	}
	if exp.MonitorTransport {
		mt := b.MonitorTransport()
		if mt == nil {
			t.Fatal("MonitorTransport() = nil, want non-nil (backend advertises monitoring)")
		}
		if mt.GuestDevice() == "" {
			t.Error("MonitorTransport().GuestDevice() is empty; the guest device path is required")
		}
	}

	// --- Type-assertion-style optionals (free-standing interfaces) ---
	tr, isTR := b.(backend.ToolRequirer)
	if isTR != exp.ToolRequirer {
		t.Errorf("ToolRequirer implemented = %v, want %v", isTR, exp.ToolRequirer)
	}
	if exp.ToolRequirer && isTR {
		assertRequiredTools(t, tr)
	}

	if _, isTV := b.(backend.TemplateValidator); isTV != exp.TemplateValidator {
		t.Errorf("TemplateValidator implemented = %v, want %v", isTV, exp.TemplateValidator)
	}

	if _, isEPS := b.(backend.EgressProviderSetter); isEPS != exp.EgressProviderSetter {
		t.Errorf("EgressProviderSetter implemented = %v, want %v", isEPS, exp.EgressProviderSetter)
	}

	if _, isSPS := b.(backend.StorageProviderSetter); isSPS != exp.StorageProviderSetter {
		t.Errorf("StorageProviderSetter implemented = %v, want %v", isSPS, exp.StorageProviderSetter)
	}

	if _, isND := b.(backend.NetworkDefaulter); isND != exp.NetworkDefaulter {
		t.Errorf("NetworkDefaulter implemented = %v, want %v", isND, exp.NetworkDefaulter)
	}
}

// assertRequiredTools asserts the ToolRequirer contract: a non-empty list of
// well-formed tool descriptors (each has a Name and a UsedBy explanation).
func assertRequiredTools(t *testing.T, tr backend.ToolRequirer) {
	t.Helper()
	tools := tr.RequiredTools()
	if len(tools) == 0 {
		t.Error("RequiredTools() is empty; a ToolRequirer must declare at least one tool")
	}
	for i, tool := range tools {
		if tool.Name == "" {
			t.Errorf("RequiredTools()[%d].Name is empty", i)
		}
		if tool.UsedBy == "" {
			t.Errorf("RequiredTools()[%d] (%q).UsedBy is empty; every tool must explain what it is used by", i, tool.Name)
		}
	}
}

// testInstance builds a well-formed, in-memory instance for the pure-contract
// assertions. Beyond the fields the contract reads directly (name, DNS/HTTP
// ports), it carries enough network detail (bridge/vnet, subnet, gateway) that
// both real backends can RENDER their DryRun config from it. Nothing here
// reaches a hypervisor or the filesystem; MACAddress is filled per-backend in
// assertDryRun from that backend's own generator.
func testInstance() *config.Instance {
	return &config.Instance{
		Name:    "conformance",
		Base:    "ubuntu-24.04",
		CPUs:    2,
		Memory:  4096,
		Disk:    "20G",
		Bridge:  "vmnet7", // valid for vmware's vnet check; ignored by libvirt render
		Subnet:  "10.10.10.0/24",
		Gateway: "10.10.10.1",
		DNS:     config.DNSConfig{Port: 15353},
		HTTP:    config.HTTPConfig{Port: 18080},
	}
}
