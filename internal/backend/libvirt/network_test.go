//go:build linux

package libvirt

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestNetworkCreateDefinesNetworkXML(t *testing.T) {
	mock := installMock(t, nil, nil)
	m := &NetworkManager{}

	if err := m.Create(context.Background(), fullInstance()); err != nil {
		t.Fatalf("Create: %v", err)
	}

	call := findCall(mock.Calls, "net-define")
	if call == nil {
		t.Fatalf("Create did not issue net-define; calls=%+v", mock.Calls)
	}
	if call.Name != cmdVirsh {
		t.Errorf("net-define command = %q, want virsh", call.Name)
	}
	if !argsHaveConnection(call.Args) {
		t.Errorf("net-define args missing connection: %v", call.Args)
	}
	if !slices.Contains(call.Args, "/dev/stdin") {
		t.Errorf("net-define args missing /dev/stdin: %v", call.Args)
	}
	// The generated network XML wires the instance bridge and gateway. Guests are
	// statically addressed (cloud-init), so there is no DHCP block.
	for _, want := range []string{
		fmt.Sprintf("<bridge name='%s'", fullInstance().Bridge),
		"ip address='10.10.10.1'",
	} {
		if !strings.Contains(call.Stdin, want) {
			t.Errorf("network XML missing %q\ngot:\n%s", want, call.Stdin)
		}
	}
	if strings.Contains(call.Stdin, "<dhcp") {
		t.Errorf("network XML must NOT contain a <dhcp> block\ngot:\n%s", call.Stdin)
	}
}

func TestNetworkCreateInvalidGatewayRejected(t *testing.T) {
	installMock(t, nil, nil)
	m := &NetworkManager{}
	inst := fullInstance()
	inst.Gateway = "not-an-ip"
	if err := m.Create(context.Background(), inst); err == nil {
		t.Fatal("Create should reject an invalid gateway")
	}
}

func TestNetworkStartStopArgVectors(t *testing.T) {
	tests := []struct {
		name   string
		call   func(m *NetworkManager) error
		subcmd string
	}{
		{"start", func(m *NetworkManager) error { return m.Start(context.Background(), "abox-dev") }, "net-start"},
		{"stop", func(m *NetworkManager) error { return m.Stop(context.Background(), "abox-dev") }, "net-destroy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := installMock(t, nil, nil)
			m := &NetworkManager{}
			if err := tt.call(m); err != nil {
				t.Fatalf("%s: %v", tt.name, err)
			}
			call := findCall(mock.Calls, tt.subcmd)
			if call == nil {
				t.Fatalf("%s did not issue %s; calls=%+v", tt.name, tt.subcmd, mock.Calls)
			}
			idx := slices.Index(call.Args, tt.subcmd)
			if got := call.Args[idx+1:]; !slices.Equal(got, []string{"abox-dev"}) {
				t.Errorf("%s trailing args = %v, want [abox-dev]", tt.name, got)
			}
		})
	}
}

func TestNetworkDeleteDestroysThenUndefines(t *testing.T) {
	mock := installMock(t, nil, nil)
	m := &NetworkManager{}
	if err := m.Delete(context.Background(), "abox-dev"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// Delete stops (net-destroy, best-effort) then undefines.
	if findCall(mock.Calls, "net-destroy") == nil {
		t.Errorf("Delete should best-effort net-destroy; calls=%+v", mock.Calls)
	}
	undef := findCall(mock.Calls, "net-undefine")
	if undef == nil {
		t.Fatalf("Delete did not issue net-undefine; calls=%+v", mock.Calls)
	}
	if !slices.Contains(undef.Args, "abox-dev") {
		t.Errorf("net-undefine missing network name: %v", undef.Args)
	}
}

func TestNetworkExistsAndIsActive(t *testing.T) {
	tests := []struct {
		name   string
		fn     func(m *NetworkManager) bool
		subcmd string
		flag   string // extra flag that must (Exists) or must not (IsActive) be present
	}{
		{"exists", func(m *NetworkManager) bool { return m.Exists("abox-dev") }, "net-list", "--all"},
		{"isactive", func(m *NetworkManager) bool { return m.IsActive("abox-dev") }, "net-list", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := installMock(t, func(name string, args ...string) (string, error) {
				return "abox-dev\n", nil
			}, nil)
			m := &NetworkManager{}
			if !tt.fn(m) {
				t.Errorf("%s should be true when the name appears in output", tt.name)
			}
			call := findCall(mock.Calls, tt.subcmd)
			if call == nil {
				t.Fatalf("%s did not issue net-list; calls=%+v", tt.name, mock.Calls)
			}
			// Exists lists --all (active + inactive); IsActive omits --all.
			hasAll := slices.Contains(call.Args, "--all")
			if tt.name == "exists" && !hasAll {
				t.Errorf("Exists should pass --all: %v", call.Args)
			}
			if tt.name == "isactive" && hasAll {
				t.Errorf("IsActive should NOT pass --all: %v", call.Args)
			}
		})
	}

	// Negative: name absent from output.
	installMock(t, func(name string, args ...string) (string, error) {
		return "some-other-net\n", nil
	}, nil)
	m := &NetworkManager{}
	if m.Exists("abox-dev") {
		t.Error("Exists should be false when name absent")
	}
	if m.IsActive("abox-dev") {
		t.Error("IsActive should be false when name absent")
	}
}

func TestNetworkExistsErrorIsFalse(t *testing.T) {
	installMock(t, func(name string, args ...string) (string, error) {
		return "", fmt.Errorf("connection refused")
	}, nil)
	m := &NetworkManager{}
	if m.Exists("abox-dev") {
		t.Error("Exists should be false on virsh error")
	}
}
