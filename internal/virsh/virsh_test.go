package virsh

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/config"
)

// setupMock installs a MockCommander and returns a cleanup function.
func setupMock(runFunc func(name string, args ...string) (string, error)) func() {
	mock := &MockCommander{RunFunc: runFunc}
	prev := SetCommander(mock)
	return func() { SetCommander(prev) }
}

func TestDomainExists(t *testing.T) {
	tests := []struct {
		name   string
		output string
		domain string
		want   bool
	}{
		{"found", "vm1\nabox-dev\nvm2\n", "abox-dev", true},
		{"not found", "vm1\nvm2\n", "abox-dev", false},
		{"empty output", "", "abox-dev", false},
		{"no substring match", "abox-dev-extra\n", "abox-dev", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := setupMock(func(name string, args ...string) (string, error) {
				return tt.output, nil
			})
			defer cleanup()

			got := DomainExists(tt.domain)
			if got != tt.want {
				t.Errorf("DomainExists(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}

	t.Run("virsh error returns false", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			return "", fmt.Errorf("connection refused")
		})
		defer cleanup()

		if DomainExists("test") {
			t.Error("expected false when virsh fails")
		}
	})
}

func TestDomainIsRunning(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{"running", "running\n", true},
		{"shut off", "shut off\n", false},
		{"paused", "paused\n", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := setupMock(func(name string, args ...string) (string, error) {
				return tt.output, nil
			})
			defer cleanup()

			got := DomainIsRunning("test")
			if got != tt.want {
				t.Errorf("DomainIsRunning() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("virsh error returns false", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			return "", fmt.Errorf("error")
		})
		defer cleanup()

		if DomainIsRunning("test") {
			t.Error("expected false on error")
		}
	})
}

func TestDomainState(t *testing.T) {
	tests := []struct {
		name   string
		output string
		err    error
		want   string
	}{
		{"running", "running\n", nil, "running"},
		{"shut off", "shut off\n", nil, "shut off"},
		{"paused", "  paused  \n", nil, "paused"},
		{"error", "", fmt.Errorf("err"), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := setupMock(func(name string, args ...string) (string, error) {
				return tt.output, tt.err
			})
			defer cleanup()

			got := DomainState("test")
			if got != tt.want {
				t.Errorf("DomainState() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetDomainUUID(t *testing.T) {
	t.Run("valid UUID", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			return `<domain><uuid>550e8400-e29b-41d4-a716-446655440000</uuid></domain>`, nil
		})
		defer cleanup()

		got := GetDomainUUID("test")
		if got != "550e8400-e29b-41d4-a716-446655440000" {
			t.Errorf("got %q, want UUID", got)
		}
	})

	t.Run("virsh error returns empty", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			return "", fmt.Errorf("error")
		})
		defer cleanup()

		if got := GetDomainUUID("test"); got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})

	t.Run("missing UUID returns empty", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			return `<domain><name>test</name></domain>`, nil
		})
		defer cleanup()

		if got := GetDomainUUID("test"); got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})
}

func TestGetNWFilterUUID(t *testing.T) {
	t.Run("valid UUID", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			return `<filter><uuid>abcd1234-5678-90ef-abcd-1234567890ef</uuid></filter>`, nil
		})
		defer cleanup()

		got := GetNWFilterUUID("test")
		if got != "abcd1234-5678-90ef-abcd-1234567890ef" {
			t.Errorf("got %q, want UUID", got)
		}
	})

	t.Run("error returns empty", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			return "", fmt.Errorf("error")
		})
		defer cleanup()

		if got := GetNWFilterUUID("test"); got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})
}

func TestNWFilterExists(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			return " UUID                                  Name\n" +
				"-----------------------------------------------------------\n" +
				" 550e8400-e29b-41d4-a716-446655440000  allow-arp\n" +
				" 660e8400-e29b-41d4-a716-446655440000  abox-dev-traffic\n", nil
		})
		defer cleanup()

		if !NWFilterExists("abox-dev-traffic") {
			t.Error("expected true")
		}
	})

	t.Run("not found", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			return " UUID                                  Name\n" +
				"-----------------------------------------------------------\n" +
				" 550e8400-e29b-41d4-a716-446655440000  allow-arp\n", nil
		})
		defer cleanup()

		if NWFilterExists("abox-dev-traffic") {
			t.Error("expected false")
		}
	})

	t.Run("no substring match", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			return " UUID  Name\n" +
				" 123   abox-dev-traffic-extra\n", nil
		})
		defer cleanup()

		if NWFilterExists("abox-dev-traffic") {
			t.Error("expected false for substring mismatch")
		}
	})
}

func TestNetworkExists(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			return "default\nabox-dev\n", nil
		})
		defer cleanup()

		if !NetworkExists("abox-dev") {
			t.Error("expected true")
		}
	})

	t.Run("not found", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			return "default\n", nil
		})
		defer cleanup()

		if NetworkExists("abox-dev") {
			t.Error("expected false")
		}
	})

	t.Run("empty output", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			return "", nil
		})
		defer cleanup()

		if NetworkExists("abox-dev") {
			t.Error("expected false on empty output")
		}
	})
}

func TestNetworkIsActive(t *testing.T) {
	t.Run("active", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			return "default\nabox-dev\n", nil
		})
		defer cleanup()

		if !NetworkIsActive("abox-dev") {
			t.Error("expected true")
		}
	})

	t.Run("inactive", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			return "default\n", nil
		})
		defer cleanup()

		if NetworkIsActive("abox-dev") {
			t.Error("expected false")
		}
	})
}

func TestSnapshotExists(t *testing.T) {
	t.Run("exists", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			return "clean-state\nother-snap\n", nil
		})
		defer cleanup()

		if !SnapshotExists("abox-dev", "clean-state") {
			t.Error("expected true")
		}
	})

	t.Run("not exists", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			return "other-snap\n", nil
		})
		defer cleanup()

		if SnapshotExists("abox-dev", "clean-state") {
			t.Error("expected false")
		}
	})
}

func TestListSnapshots(t *testing.T) {
	t.Run("multiple snapshots", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			// Handle both snapshot-list --name and snapshot-info calls
			if slices.Contains(args, "snapshot-info") {
				return "Name:           snap1\nCreation Time:  2024-01-01\nState:          running\n", nil
			}
			return "snap1\nsnap2\n", nil
		})
		defer cleanup()

		snaps, err := ListSnapshots("abox-dev")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(snaps) != 2 {
			t.Errorf("got %d snapshots, want 2", len(snaps))
		}
	})

	t.Run("empty list", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			return "\n", nil
		})
		defer cleanup()

		snaps, err := ListSnapshots("abox-dev")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(snaps) != 0 {
			t.Errorf("got %d snapshots, want 0", len(snaps))
		}
	})
}

func TestGetSnapshotInfo(t *testing.T) {
	t.Run("all fields", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			return "Name:           clean-state\n" +
				"Creation Time:  2024-01-15 10:30:00 -0500\n" +
				"State:          running\n" +
				"Parent:         base-snap\n" +
				"Current:        yes\n", nil
		})
		defer cleanup()

		info, err := GetSnapshotInfo("abox-dev", "clean-state")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if info.Name != "clean-state" {
			t.Errorf("Name = %q, want %q", info.Name, "clean-state")
		}
		if info.State != "running" {
			t.Errorf("State = %q, want %q", info.State, "running")
		}
		if info.Parent != "base-snap" {
			t.Errorf("Parent = %q, want %q", info.Parent, "base-snap")
		}
		if !info.Current {
			t.Error("Current should be true")
		}
	})

	t.Run("missing fields", func(t *testing.T) {
		cleanup := setupMock(func(name string, args ...string) (string, error) {
			return "Name:           snap1\nState:          shutoff\n", nil
		})
		defer cleanup()

		info, err := GetSnapshotInfo("abox-dev", "snap1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if info.Parent != "" {
			t.Errorf("Parent = %q, want empty", info.Parent)
		}
		if info.Current {
			t.Error("Current should be false")
		}
	})
}

func TestDeleteDomain_StopsBeforeUndefine(t *testing.T) {
	var calls []string
	mock := &MockCommander{
		RunFunc: func(name string, args ...string) (string, error) {
			call := strings.Join(args, " ")
			calls = append(calls, call)
			// destroy fails (domain not running)
			if strings.Contains(call, "destroy") {
				return "", fmt.Errorf("domain not running")
			}
			return "", nil
		},
	}
	prev := SetCommander(mock)
	defer SetCommander(prev)

	err := DeleteDomain("test")
	if err != nil {
		t.Fatalf("DeleteDomain should succeed even if destroy fails: %v", err)
	}
}

func TestDeleteNetwork_StopsBeforeUndefine(t *testing.T) {
	mock := &MockCommander{
		RunFunc: func(name string, args ...string) (string, error) {
			call := strings.Join(args, " ")
			if strings.Contains(call, "net-destroy") {
				return "", fmt.Errorf("network not active")
			}
			return "", nil
		},
	}
	prev := SetCommander(mock)
	defer SetCommander(prev)

	err := DeleteNetwork("test")
	if err != nil {
		t.Fatalf("DeleteNetwork should succeed even if net-destroy fails: %v", err)
	}
}

func TestApplyNWFilter_RejectsInvalidMAC(t *testing.T) {
	mock := &MockCommander{}
	prev := SetCommander(mock)
	defer SetCommander(prev)

	err := ApplyNWFilter("dom", "net", "filter", "invalid-mac", 2)
	if err == nil {
		t.Fatal("expected error for invalid MAC")
	}
	if len(mock.Calls) > 0 {
		t.Error("should not have called virsh with invalid MAC")
	}
}

func TestRemoveNWFilter_RejectsInvalidMAC(t *testing.T) {
	mock := &MockCommander{}
	prev := SetCommander(mock)
	defer SetCommander(prev)

	err := RemoveNWFilter("dom", "net", "invalid-mac", 2)
	if err == nil {
		t.Fatal("expected error for invalid MAC")
	}
	if len(mock.Calls) > 0 {
		t.Error("should not have called virsh with invalid MAC")
	}
}

func TestCreateSnapshot_RejectsInvalidName(t *testing.T) {
	mock := &MockCommander{}
	prev := SetCommander(mock)
	defer SetCommander(prev)

	err := CreateSnapshot("dom", "invalid name!", "desc")
	if err == nil {
		t.Fatal("expected error for invalid snapshot name")
	}
	if len(mock.Calls) > 0 {
		t.Error("should not have called virsh with invalid name")
	}
}

func TestStartNetwork_PropagatesError(t *testing.T) {
	cleanup := setupMock(func(name string, args ...string) (string, error) {
		return "", fmt.Errorf("network not found")
	})
	defer cleanup()

	err := StartNetwork("test")
	if err == nil {
		t.Fatal("expected error to be propagated")
	}
	if !strings.Contains(err.Error(), "failed to start network") {
		t.Errorf("expected wrapped error, got: %v", err)
	}
}

func TestNetworkXML(t *testing.T) {
	inst := &config.Instance{
		Name:       "dev",
		Bridge:     "abox-dev",
		Gateway:    "192.168.50.1",
		IPAddress:  "192.168.50.2",
		MACAddress: "52:54:00:ab:cd:ef",
	}

	xml, err := NetworkXML(inst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(xml, "abox-dev") {
		t.Error("XML should contain bridge name")
	}
	if !strings.Contains(xml, "192.168.50.1") {
		t.Error("XML should contain gateway")
	}
	// Guests are statically addressed (cloud-init); libvirt runs no DHCP server.
	if strings.Contains(xml, "<dhcp") {
		t.Error("static network XML must NOT contain a <dhcp> block")
	}
	if strings.Contains(xml, "dhcp-option") {
		t.Error("static network XML must NOT set any dhcp-option")
	}
	// The network is isolated (host-only): no <forward> element and no NAT, so the
	// guest has no uplink and egress is provided only by the host on its behalf.
	if strings.Contains(xml, "<forward") {
		t.Error("isolated network XML must NOT contain a <forward> element")
	}
	if strings.Contains(xml, "nat") {
		t.Error("isolated network XML must NOT contain NAT")
	}
	// Hardening: STP is disabled on the host-only bridge (no uplink/loop; removes
	// BPDU processing as guest-facing attack surface).
	if !strings.Contains(xml, "stp='off'") {
		t.Error("host-only bridge should disable STP")
	}
	if strings.Contains(xml, "stp='on'") {
		t.Error("host-only bridge must NOT enable STP")
	}
}

func TestNWFilterXML(t *testing.T) {
	inst := &config.Instance{
		Name:    "dev",
		Gateway: "192.168.50.1",
		DNS:     config.DNSConfig{Port: 5353},
		HTTP:    config.HTTPConfig{Port: 8080},
	}

	t.Run("without UUID", func(t *testing.T) {
		xml, err := NWFilterXML(inst, "", 53)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(xml, "dev") {
			t.Error("XML should contain instance name")
		}
		// Guest-facing DNS port is templated from the policy, not hardcoded.
		if !strings.Contains(xml, "dstportstart='53'") {
			t.Error("XML should allow the guest-facing DNS port")
		}
	})

	t.Run("with UUID", func(t *testing.T) {
		xml, err := NWFilterXML(inst, "550e8400-e29b-41d4-a716-446655440000", 53)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(xml, "550e8400-e29b-41d4-a716-446655440000") {
			t.Error("XML should preserve UUID")
		}
	})

	t.Run("gateway ICMP permitted, no DHCP rules", func(t *testing.T) {
		xml, err := NWFilterXML(inst, "", 53)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(xml, "<icmp") {
			t.Error("XML should always include the gateway ICMP rule")
		}
		// Guests are statically addressed; there is no DHCP handshake to permit.
		if strings.Contains(xml, "dstportstart='67'") || strings.Contains(xml, "srcportstart='67'") {
			t.Error("XML must NOT include DHCP rules (static addressing)")
		}
	})

	t.Run("L2 anti-spoofing filterrefs", func(t *testing.T) {
		xml, err := NWFilterXML(inst, "", 53)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Pin the guest to its assigned MAC and prevent ARP spoofing on the bridge.
		if !strings.Contains(xml, "<filterref filter='no-mac-spoofing'/>") {
			t.Error("XML should reference the no-mac-spoofing filter")
		}
		if !strings.Contains(xml, "<filterref filter='no-arp-spoofing'/>") {
			t.Error("XML should reference the no-arp-spoofing filter")
		}
	})

	t.Run("stateful SSH-only inbound policy", func(t *testing.T) {
		xml, err := NWFilterXML(inst, "", 53)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Host->guest SSH is the only NEW inbound connection permitted. Pin the
		// rule's DIRECTION together with the protocol/port/state so a direction
		// inversion, wrong protocol, or missing state is caught — not just any
		// mention of "22".
		if !strings.Contains(xml, "direction='in' priority='150'>\n    <tcp dstportstart='22' dstportend='22' state='NEW'/>") {
			t.Error("XML should allow inbound SSH as a NEW tcp:22 connection on direction='in'")
		}
		// Return traffic for established connections is admitted explicitly in
		// both directions (the standard stateful return path).
		if c := strings.Count(xml, "<all state='ESTABLISHED,RELATED'/>"); c != 2 {
			t.Errorf("expected ESTABLISHED,RELATED accepts in both directions, got %d", c)
		}
		// Default deny in BOTH directions; without these the filter is fail-open.
		if !strings.Contains(xml, "action='drop' direction='in'") {
			t.Error("XML must default-deny inbound")
		}
		if !strings.Contains(xml, "action='drop' direction='out'") {
			t.Error("XML must default-deny outbound")
		}
	})

	// <all/> matches IPv4 only, so a separate <all-ipv6/> terminal drop is
	// required in both directions or a guest could reach host services over IPv6.
	t.Run("IPv6 default-deny in both directions", func(t *testing.T) {
		xml, err := NWFilterXML(inst, "", 53)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(xml, "direction='in' priority='999'>\n    <all-ipv6/>") {
			t.Error("XML must drop inbound IPv6 at terminal priority")
		}
		if !strings.Contains(xml, "direction='out' priority='999'>\n    <all-ipv6/>") {
			t.Error("XML must drop outbound IPv6 at terminal priority")
		}
	})
}

func TestDomainXMLWithOptions(t *testing.T) {
	inst := &config.Instance{
		Name:       "dev",
		CPUs:       4,
		Memory:     8192,
		Bridge:     "abox-dev",
		MACAddress: "52:54:00:ab:cd:ef",
	}
	paths := &config.Paths{
		Disk:         "/var/lib/libvirt/images/abox/dev.qcow2",
		CloudInitISO: "/tmp/test-cloud-init.iso",
	}

	t.Run("basic generation", func(t *testing.T) {
		xml, err := DomainXMLWithOptions(inst, paths, DomainXMLOptions{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(xml, "dev") {
			t.Error("XML should contain name")
		}
		if !strings.Contains(xml, "8192") || !strings.Contains(xml, "8388608") {
			// Memory in MB or KiB depending on template
			if !strings.Contains(xml, "8192") {
				t.Error("XML should contain memory")
			}
		}
		if !strings.Contains(xml, "abox-dev") {
			t.Error("XML should contain network name")
		}
		// Hardening: pinned q35 machine type (trims legacy i440fx device surface).
		if !strings.Contains(xml, "machine='q35'") {
			t.Error("XML should pin the q35 machine type")
		}
		// Hardening: virtio devices are modern-only (virtio-non-transitional).
		if !strings.Contains(xml, "<model type='virtio-non-transitional'/>") {
			t.Error("interface should use virtio-non-transitional model")
		}
		if !strings.Contains(xml, "<rng model='virtio-non-transitional'>") {
			t.Error("rng should use virtio-non-transitional model")
		}
	})

	t.Run("with monitor", func(t *testing.T) {
		monPaths := &config.Paths{
			Disk:          "/var/lib/libvirt/images/abox/dev.qcow2",
			MonitorSocket: "/tmp/monitor.sock",
		}
		xml, err := DomainXMLWithOptions(inst, monPaths, DomainXMLOptions{MonitorEnabled: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(xml, "virtio-serial") {
			t.Error("XML should contain virtio-serial when monitor enabled")
		}
		// Hardening: the virtio-serial controller is modern-only too.
		if !strings.Contains(xml, "type='virtio-serial' index='0' model='virtio-non-transitional'") {
			t.Error("virtio-serial controller should use virtio-non-transitional model")
		}
	})
}

func TestEmbeddedDomainTemplate(t *testing.T) {
	tmpl := EmbeddedDomainTemplate()
	if tmpl == "" {
		t.Fatal("EmbeddedDomainTemplate() returned empty string")
	}
	if err := ValidateTemplate(tmpl); err != nil {
		t.Errorf("embedded template should be valid: %v", err)
	}
}

func TestValidateTemplate(t *testing.T) {
	t.Run("valid template", func(t *testing.T) {
		tmpl := `<domain type="kvm"><name>{{.Name}}</name><memory>{{.Memory}}</memory></domain>`
		if err := ValidateTemplate(tmpl); err != nil {
			t.Errorf("ValidateTemplate() error = %v", err)
		}
	})

	t.Run("syntax error", func(t *testing.T) {
		tmpl := `<domain>{{.Name}</domain>`
		err := ValidateTemplate(tmpl)
		if err == nil {
			t.Fatal("ValidateTemplate() should return error for syntax error")
		}
		if !strings.Contains(err.Error(), "template syntax error") {
			t.Errorf("error should mention syntax: %v", err)
		}
	})

	t.Run("invalid field reference", func(t *testing.T) {
		tmpl := `<domain>{{.NonExistentField}}</domain>`
		err := ValidateTemplate(tmpl)
		if err == nil {
			t.Fatal("ValidateTemplate() should return error for invalid field")
		}
		if !strings.Contains(err.Error(), "template execution error") {
			t.Errorf("error should mention execution: %v", err)
		}
	})

	t.Run("conditional field is not checked", func(t *testing.T) {
		// Fields inside {{if}} blocks with zero-value conditions are not executed
		tmpl := `<domain>{{if .Name}}{{.NonExistentField}}{{end}}</domain>`
		if err := ValidateTemplate(tmpl); err != nil {
			t.Errorf("conditional block should not cause error with zero-value data: %v", err)
		}
	})
}

func TestDomainXMLWithOptions_CustomTemplate(t *testing.T) {
	inst := &config.Instance{
		Name:       "dev",
		CPUs:       2,
		Memory:     4096,
		Bridge:     "abox-dev",
		MACAddress: "52:54:00:ab:cd:ef",
	}
	paths := &config.Paths{
		Disk:         "/var/lib/libvirt/images/abox/dev.qcow2",
		CloudInitISO: "/tmp/test-cloud-init.iso",
	}

	customTemplate := `<domain type="kvm">
  <name>custom-{{.Name}}</name>
  <memory unit="MiB">{{.Memory}}</memory>
  <vcpu>{{.CPUs}}</vcpu>
</domain>`

	xml, err := DomainXMLWithOptions(inst, paths, DomainXMLOptions{
		CustomTemplate: customTemplate,
	})
	if err != nil {
		t.Fatalf("DomainXMLWithOptions() error = %v", err)
	}
	if !strings.Contains(xml, "custom-dev") {
		t.Error("XML should use custom template (contain 'custom-dev')")
	}
	if !strings.Contains(xml, "4096") {
		t.Error("XML should contain memory value from custom template")
	}
}

func TestGenerateMAC(t *testing.T) {
	macRegex := regexp.MustCompile(`^52:54:00:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$`)

	mac := GenerateMAC()
	if !macRegex.MatchString(mac) {
		t.Errorf("GenerateMAC() = %q, doesn't match libvirt MAC pattern", mac)
	}

	// Consecutive calls should (almost always) produce different MACs
	mac2 := GenerateMAC()
	mac3 := GenerateMAC()
	if mac == mac2 && mac2 == mac3 {
		t.Error("three consecutive GenerateMAC() calls returned identical results")
	}
}
