//go:build linux

package libvirt

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/virsh"
)

// cmdVirsh is the expected command name for every libvirt manager invocation;
// a shared test constant so the string literal is defined once (goconst).
const cmdVirsh = "virsh"

// stateRunning is the virsh domstate value for a running domain (shared test
// literal, goconst).
const stateRunning = "running"

// fullInstance returns a complete, valid instance for the libvirt managers
// (VM/network/disk XML generation and disk paths). The package's minimal
// testInstance (traffic_test.go) is reused only where those extra fields are not
// needed.
func fullInstance() *config.Instance {
	inst := &config.Instance{
		Version:    config.CurrentInstanceVersion,
		Name:       "dev",
		Base:       "ubuntu-24.04",
		CPUs:       2,
		Memory:     4096,
		Subnet:     "10.10.10.0/24",
		Gateway:    "10.10.10.1",
		Bridge:     config.GenerateBridgeName("dev"),
		MACAddress: "52:54:00:ab:cd:ef",
		IPAddress:  "10.10.10.50",
		Disk:       "20G",
	}
	inst.DNS.Port = 42916
	inst.HTTP.Port = 43001
	return inst
}

// testPaths returns resolved paths rooted under a temp XDG dir. It does not
// touch the filesystem beyond what the caller does.
func testPaths(t *testing.T) *config.Paths {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	p, err := config.GetPaths("dev")
	if err != nil {
		t.Fatalf("GetPaths: %v", err)
	}
	return p
}

// installMock swaps in a MockCommander (recording Run + RunWithStdin calls) and
// returns the mock plus a cleanup func. runFunc/stdinFunc may be nil.
func installMock(t *testing.T,
	runFunc func(name string, args ...string) (string, error),
	stdinFunc func(name, stdin string, args ...string) error,
) *virsh.MockCommander {
	t.Helper()
	mock := &virsh.MockCommander{RunFunc: runFunc, RunWithStdinFunc: stdinFunc}
	prev := virsh.SetCommander(mock)
	t.Cleanup(func() { virsh.SetCommander(prev) })
	return mock
}

// findCall returns the first recorded call whose args contain subcmd, or nil.
func findCall(calls []virsh.MockCall, subcmd string) *virsh.MockCall {
	for i := range calls {
		if slices.Contains(calls[i].Args, subcmd) {
			return &calls[i]
		}
	}
	return nil
}

func TestVMCreateDefinesDomainXML(t *testing.T) {
	paths := testPaths(t)
	mock := installMock(t, nil, nil)
	m := &VMManager{}

	if err := m.Create(context.Background(), fullInstance(), paths,
		backend.VMCreateOptions{AssumeCloudInitExists: true}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Create routes through DefineDomain -> RunWithStdin("virsh", xml, ...define /dev/stdin).
	call := findCall(mock.Calls, "define")
	if call == nil {
		t.Fatalf("Create did not issue a virsh define; calls=%+v", mock.Calls)
	}
	if call.Name != cmdVirsh {
		t.Errorf("define command = %q, want virsh", call.Name)
	}
	// The stdin carries the generated domain XML.
	for _, want := range []string{
		"<name>abox-dev</name>",
		`<memory unit='MiB'>4096</memory>`,
	} {
		if !strings.Contains(call.Stdin, want) {
			t.Errorf("domain XML stdin missing %q\ngot:\n%s", want, call.Stdin)
		}
	}
	// AssumeCloudInitExists forces the cloud-init CDROM device even though the ISO
	// does not exist on disk.
	if !strings.Contains(call.Stdin, paths.CloudInitISO) {
		t.Errorf("AssumeCloudInitExists should include cloud-init ISO %q in XML:\n%s",
			paths.CloudInitISO, call.Stdin)
	}
	// Args carry the system connection and the /dev/stdin sentinel.
	if !slices.Contains(call.Args, "/dev/stdin") {
		t.Errorf("define args missing /dev/stdin: %v", call.Args)
	}
	if !argsHaveConnection(call.Args) {
		t.Errorf("define args missing -c qemu:///system: %v", call.Args)
	}
}

func TestVMCreateInvalidMACRejected(t *testing.T) {
	paths := testPaths(t)
	installMock(t, nil, nil)
	m := &VMManager{}
	inst := fullInstance()
	inst.MACAddress = "not-a-mac"
	if err := m.Create(context.Background(), inst, paths, backend.VMCreateOptions{}); err == nil {
		t.Fatal("Create should reject an invalid MAC address")
	}
}

func TestVMRedefinePreservesUUID(t *testing.T) {
	paths := testPaths(t)
	const uuid = "12345678-1234-1234-1234-123456789abc"

	// GetUUID (dumpxml) returns a domain XML carrying the UUID; define captures XML.
	var defineXML string
	installMock(t,
		func(name string, args ...string) (string, error) {
			if slices.Contains(args, "dumpxml") {
				return fmt.Sprintf("<domain><uuid>%s</uuid></domain>", uuid), nil
			}
			return "", nil
		},
		func(name, stdin string, args ...string) error {
			if slices.Contains(args, "define") {
				defineXML = stdin
			}
			return nil
		},
	)

	m := &VMManager{}
	// Redefine with an empty UUID: the manager should read the existing UUID via
	// GetUUID (dumpxml) and thread it into the regenerated XML.
	if err := m.Redefine(context.Background(), fullInstance(), paths,
		backend.VMCreateOptions{}); err != nil {
		t.Fatalf("Redefine: %v", err)
	}
	if !strings.Contains(defineXML, uuid) {
		t.Errorf("Redefine did not preserve UUID %q in domain XML:\n%s", uuid, defineXML)
	}
}

func TestVMLifecycleArgVectors(t *testing.T) {
	installMock(t, nil, nil)
	m := &VMManager{}
	ctx := context.Background()

	tests := []struct {
		name    string
		call    func() error
		subcmd  string
		wantEnd []string // trailing positional(s) after the subcommand
	}{
		{"start", func() error { return m.Start(ctx, "dev") }, "start", []string{"abox-dev"}},
		{"stop", func() error { return m.Stop(ctx, "dev") }, "shutdown", []string{"abox-dev"}},
		{"forcestop", func() error { return m.ForceStop(ctx, "dev") }, "destroy", []string{"abox-dev"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := installMock(t, nil, nil)
			if err := tt.call(); err != nil {
				t.Fatalf("%s: %v", tt.name, err)
			}
			call := findCall(mock.Calls, tt.subcmd)
			if call == nil {
				t.Fatalf("%s did not issue virsh %s; calls=%+v", tt.name, tt.subcmd, mock.Calls)
			}
			if call.Name != cmdVirsh {
				t.Errorf("%s command = %q, want virsh", tt.name, call.Name)
			}
			if !argsHaveConnection(call.Args) {
				t.Errorf("%s args missing -c qemu:///system: %v", tt.name, call.Args)
			}
			// The domain name must follow the subcommand as a positional.
			idx := slices.Index(call.Args, tt.subcmd)
			got := call.Args[idx+1:]
			if !slices.Equal(got, tt.wantEnd) {
				t.Errorf("%s trailing args = %v, want %v (full=%v)", tt.name, got, tt.wantEnd, call.Args)
			}
		})
	}
}

func TestVMRemoveArgVector(t *testing.T) {
	mock := installMock(t, nil, nil)
	m := &VMManager{}
	if err := m.Remove(context.Background(), "dev"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	// Remove destroys (best-effort) then undefines with --remove-all-storage.
	undef := findCall(mock.Calls, "undefine")
	if undef == nil {
		t.Fatalf("Remove did not issue undefine; calls=%+v", mock.Calls)
	}
	if !slices.Contains(undef.Args, "abox-dev") {
		t.Errorf("undefine missing domain name: %v", undef.Args)
	}
	if !slices.Contains(undef.Args, "--remove-all-storage") {
		t.Errorf("undefine missing --remove-all-storage: %v", undef.Args)
	}
}

func TestVMExistsParsing(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{"present", "other\nabox-dev\n", true},
		{"absent", "other\nabox-prod\n", false},
		{"substring-no-match", "abox-dev-extra\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			installMock(t, func(name string, args ...string) (string, error) {
				return tt.output, nil
			}, nil)
			m := &VMManager{}
			if got := m.Exists("dev"); got != tt.want {
				t.Errorf("Exists = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVMIsRunningAndState(t *testing.T) {
	tests := []struct {
		state       string
		wantRunning bool
		wantState   backend.VMState
	}{
		{stateRunning, true, backend.VMStateRunning},
		{"shut off", false, backend.VMStateStopped},
		{"paused", false, backend.VMStatePaused},
		{"crashed", false, backend.VMStateCrashed},
		{"gibberish", false, backend.VMStateUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.state, func(t *testing.T) {
			installMock(t, func(name string, args ...string) (string, error) {
				return tt.state + "\n", nil
			}, nil)
			m := &VMManager{}
			if got := m.IsRunning("dev"); got != tt.wantRunning {
				t.Errorf("IsRunning(%q) = %v, want %v", tt.state, got, tt.wantRunning)
			}
			if got := m.State("dev"); got != tt.wantState {
				t.Errorf("State(%q) = %v, want %v", tt.state, got, tt.wantState)
			}
		})
	}
}

func TestVMStateOnError(t *testing.T) {
	installMock(t, func(name string, args ...string) (string, error) {
		return "", fmt.Errorf("no such domain")
	}, nil)
	m := &VMManager{}
	if got := m.State("dev"); got != backend.VMStateUnknown {
		t.Errorf("State on error = %v, want unknown", got)
	}
	if m.IsRunning("dev") {
		t.Error("IsRunning on error should be false")
	}
}

func TestVMGetIPReturnsStaticConfig(t *testing.T) {
	// Guests are statically addressed: GetIP returns the instance's configured IP
	// (config.IPAddress), with no virsh/DHCP-lease lookup.
	paths := testPaths(t)
	if err := os.MkdirAll(paths.Instance, 0o755); err != nil {
		t.Fatalf("mkdir instance dir: %v", err)
	}
	inst := fullInstance()
	if err := config.Save(inst, paths); err != nil {
		t.Fatalf("Save: %v", err)
	}
	m := &VMManager{}
	ip, err := m.GetIP("dev")
	if err != nil {
		t.Fatalf("GetIP: %v", err)
	}
	if ip != inst.IPAddress {
		t.Errorf("GetIP = %q, want %q", ip, inst.IPAddress)
	}
}

func TestVMGetUUIDParsing(t *testing.T) {
	const uuid = "abcdef12-3456-7890-abcd-ef1234567890"
	installMock(t, func(name string, args ...string) (string, error) {
		if slices.Contains(args, "dumpxml") {
			return fmt.Sprintf("<domain type='kvm'><uuid>%s</uuid></domain>", uuid), nil
		}
		return "", nil
	}, nil)
	m := &VMManager{}
	if got := m.GetUUID("dev"); got != uuid {
		t.Errorf("GetUUID = %q, want %q", got, uuid)
	}
}

func TestVMGetUUIDMissing(t *testing.T) {
	installMock(t, func(name string, args ...string) (string, error) {
		return "", fmt.Errorf("domain not found")
	}, nil)
	m := &VMManager{}
	if got := m.GetUUID("dev"); got != "" {
		t.Errorf("GetUUID for missing domain = %q, want empty", got)
	}
}

// argsHaveConnection reports whether the virsh args include the system URI.
func argsHaveConnection(args []string) bool {
	for i, a := range args {
		if a == "-c" && i+1 < len(args) && args[i+1] == "qemu:///system" {
			return true
		}
	}
	return false
}
