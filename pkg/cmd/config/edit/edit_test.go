package edit

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/backend/mock"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

func testFactory() *factory.Factory {
	ios, _, _, _ := iostreams.Test()
	return &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}
}

// isolateDataDir points the config package at an empty temp data dir so
// ValidateSubnet's collision scan never reads (or collides with) the invoking
// user's real instances.
func isolateDataDir(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
}

// testPaths returns Paths whose daemon PID files do not exist, so the default
// daemonAlive check reports every daemon as not running.
func testPaths(t *testing.T) *config.Paths {
	t.Helper()
	dir := t.TempDir()
	return &config.Paths{
		DNSPIDFile:  dir + "/dns.pid",
		HTTPPIDFile: dir + "/http.pid",
	}
}

// stubDaemonAlive replaces the daemon-liveness seam for the test's duration.
func stubDaemonAlive(t *testing.T, fn func(pidFile string) bool) {
	t.Helper()
	orig := daemonAlive
	daemonAlive = fn
	t.Cleanup(func() { daemonAlive = orig })
}

// testInstance returns an instance shaped like one created on the libvirt
// backend: subnet-derived gateway/IP, a bridge network, and a fixed MAC.
func testInstance() *config.Instance {
	return &config.Instance{
		Name:       "edity",
		Backend:    "libvirt",
		Subnet:     "10.10.10.0/24",
		Gateway:    "10.10.10.1",
		IPAddress:  "10.10.10.10",
		Bridge:     "abox-edity",
		MACAddress: "52:54:00:aa:bb:cc",
	}
}

func TestNewCmdEdit_FlagParsing(t *testing.T) {
	f := testFactory()

	var gotOpts *Options
	cmd := NewCmdEdit(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"myvm", "--subnet", "10.77.0.0/24", "--cpus", "4"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts == nil {
		t.Fatal("runF was not called")
	}
	if gotOpts.Name != "myvm" {
		t.Errorf("Name = %q, want myvm", gotOpts.Name)
	}
	if gotOpts.Subnet != "10.77.0.0/24" {
		t.Errorf("Subnet = %q, want 10.77.0.0/24", gotOpts.Subnet)
	}
	if gotOpts.CPUs != 4 {
		t.Errorf("CPUs = %d, want 4", gotOpts.CPUs)
	}
}

func TestEditSubnet_SameSubnetIsFlagError(t *testing.T) {
	isolateDataDir(t)
	inst := testInstance()
	opts := &Options{Factory: testFactory(), Name: inst.Name, Subnet: inst.Subnet}

	// The backend gate runs first, so the no-op guard is only reachable on libvirt.
	be := &mock.Backend{NameFunc: func() string { return "libvirt" }}

	_, err := editSubnet(context.Background(), opts, be, inst, testPaths(t))
	if err == nil {
		t.Fatal("expected an error when the new subnet equals the current one")
	}
	var flagErr *cmdutil.ErrFlag
	if !errors.As(err, &flagErr) {
		t.Errorf("expected an ErrFlag, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "subnet is already 10.10.10.0/24") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestEditSubnet_RejectsNonLibvirtBackend(t *testing.T) {
	isolateDataDir(t)
	inst := testInstance()
	inst.Backend = "vfkit"
	opts := &Options{Factory: testFactory(), Name: inst.Name, Subnet: "10.77.0.0/24"}

	be := &mock.Backend{NameFunc: func() string { return "vfkit" }}

	_, err := editSubnet(context.Background(), opts, be, inst, testPaths(t))
	if err == nil {
		t.Fatal("expected an error on a non-libvirt backend")
	}
	want := "subnet can only be edited on the libvirt backend; the vfkit backend manages its own networks"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
}

func TestEditSubnet_RejectsRunningInstance(t *testing.T) {
	isolateDataDir(t)
	inst := testInstance()
	opts := &Options{Factory: testFactory(), Name: inst.Name, Subnet: "10.77.0.0/24"}

	be := &mock.Backend{
		NameFunc: func() string { return "libvirt" },
		VMFunc: func() backend.VMManager {
			return &mock.VMManager{IsRunningFunc: func(string) bool { return true }}
		},
	}

	_, err := editSubnet(context.Background(), opts, be, inst, testPaths(t))
	if err == nil {
		t.Fatal("expected an error when the instance is running")
	}
	if !strings.Contains(err.Error(), `instance "edity" is running; stop it before changing the subnet`) {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestEditSubnet_RejectsInvalidSubnet(t *testing.T) {
	isolateDataDir(t)
	inst := testInstance()
	// /16 (not /24) must be rejected by ValidateSubnet before any network change.
	opts := &Options{Factory: testFactory(), Name: inst.Name, Subnet: "10.77.0.0/16"}

	deleted := false
	be := &mock.Backend{
		NameFunc: func() string { return "libvirt" },
		VMFunc: func() backend.VMManager {
			return &mock.VMManager{IsRunningFunc: func(string) bool { return false }}
		},
		NetworkFunc: func() backend.NetworkManager {
			return &mock.NetworkManager{DeleteFunc: func(context.Context, string) error {
				deleted = true
				return nil
			}}
		},
	}

	_, err := editSubnet(context.Background(), opts, be, inst, testPaths(t))
	if err == nil {
		t.Fatal("expected an error for a non-/24 subnet")
	}
	if deleted {
		t.Error("network must not be deleted when subnet validation fails")
	}
	if inst.Subnet != "10.10.10.0/24" {
		t.Errorf("instance subnet mutated on validation failure: %q", inst.Subnet)
	}
}

func TestEditSubnet_SuccessMutatesConfigAndDeletesNetwork(t *testing.T) {
	isolateDataDir(t)
	inst := testInstance()
	opts := &Options{Factory: testFactory(), Name: inst.Name, Subnet: "10.77.0.0/24"}

	var deletedNetwork string
	be := &mock.Backend{
		NameFunc: func() string { return "libvirt" },
		VMFunc: func() backend.VMManager {
			return &mock.VMManager{IsRunningFunc: func(string) bool { return false }}
		},
		NetworkFunc: func() backend.NetworkManager {
			return &mock.NetworkManager{
				ExistsFunc: func(string) bool { return true },
				DeleteFunc: func(_ context.Context, name string) error {
					deletedNetwork = name
					return nil
				},
			}
		},
	}

	change, err := editSubnet(context.Background(), opts, be, inst, testPaths(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if deletedNetwork != "abox-edity" {
		t.Errorf("Network().Delete called with %q, want abox-edity", deletedNetwork)
	}
	if inst.Subnet != "10.77.0.0/24" {
		t.Errorf("Subnet = %q, want 10.77.0.0/24", inst.Subnet)
	}
	if inst.Gateway != "10.77.0.1" {
		t.Errorf("Gateway = %q, want 10.77.0.1", inst.Gateway)
	}
	if inst.IPAddress != "10.77.0.10" {
		t.Errorf("IPAddress = %q, want 10.77.0.10 (guest is always .10)", inst.IPAddress)
	}
	// Bridge and MAC are referenced by the domain XML and must not change.
	if inst.Bridge != "abox-edity" || inst.MACAddress != "52:54:00:aa:bb:cc" {
		t.Errorf("Bridge/MAC changed: %q / %q", inst.Bridge, inst.MACAddress)
	}
	if !strings.Contains(change, "10.10.10.0/24 -> 10.77.0.0/24") {
		t.Errorf("change description = %q", change)
	}
}

func TestEditSubnet_SkipsDeleteWhenNetworkMissing(t *testing.T) {
	isolateDataDir(t)
	inst := testInstance()
	opts := &Options{Factory: testFactory(), Name: inst.Name, Subnet: "10.77.0.0/24"}

	be := &mock.Backend{
		NameFunc: func() string { return "libvirt" },
		VMFunc: func() backend.VMManager {
			return &mock.VMManager{IsRunningFunc: func(string) bool { return false }}
		},
		NetworkFunc: func() backend.NetworkManager {
			return &mock.NetworkManager{
				ExistsFunc: func(string) bool { return false },
				DeleteFunc: func(context.Context, string) error {
					t.Error("Network().Delete must not be called when the network does not exist")
					return nil
				},
			}
		},
	}

	if _, err := editSubnet(context.Background(), opts, be, inst, testPaths(t)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inst.Subnet != "10.77.0.0/24" {
		t.Errorf("Subnet = %q, want 10.77.0.0/24", inst.Subnet)
	}
}

func TestEditSubnet_DeleteFailureAbortsBeforeMutation(t *testing.T) {
	isolateDataDir(t)
	inst := testInstance()
	opts := &Options{Factory: testFactory(), Name: inst.Name, Subnet: "10.77.0.0/24"}

	deleteErr := errors.New("boom: net-undefine failed")
	be := &mock.Backend{
		NameFunc: func() string { return "libvirt" },
		VMFunc: func() backend.VMManager {
			return &mock.VMManager{IsRunningFunc: func(string) bool { return false }}
		},
		NetworkFunc: func() backend.NetworkManager {
			return &mock.NetworkManager{
				ExistsFunc: func(string) bool { return true },
				DeleteFunc: func(context.Context, string) error { return deleteErr },
			}
		},
	}

	_, err := editSubnet(context.Background(), opts, be, inst, testPaths(t))
	if err == nil {
		t.Fatal("expected the edit to fail when the stale network cannot be deleted")
	}
	if !errors.Is(err, deleteErr) {
		t.Errorf("expected the error to wrap the Delete error, got: %v", err)
	}
	// The instance must be untouched so the caller never saves a config that
	// diverges from the still-defined old-subnet libvirt network.
	if inst.Subnet != "10.10.10.0/24" || inst.Gateway != "10.10.10.1" || inst.IPAddress != "10.10.10.10" {
		t.Errorf("instance mutated despite Delete failure: subnet=%q gateway=%q ip=%q",
			inst.Subnet, inst.Gateway, inst.IPAddress)
	}
}

func TestEditSubnet_RejectsLiveFilterDaemons(t *testing.T) {
	isolateDataDir(t)
	inst := testInstance()
	opts := &Options{Factory: testFactory(), Name: inst.Name, Subnet: "10.77.0.0/24"}
	paths := testPaths(t)

	// Simulate the stale-daemon window a failed start leaves behind: the VM is
	// stopped but the httpfilter (bound to the OLD gateway) is still alive.
	stubDaemonAlive(t, func(pidFile string) bool { return pidFile == paths.HTTPPIDFile })

	be := &mock.Backend{
		NameFunc: func() string { return "libvirt" },
		VMFunc: func() backend.VMManager {
			return &mock.VMManager{IsRunningFunc: func(string) bool { return false }}
		},
		NetworkFunc: func() backend.NetworkManager {
			return &mock.NetworkManager{DeleteFunc: func(context.Context, string) error {
				t.Error("network must not be deleted while filter daemons are alive")
				return nil
			}}
		},
	}

	_, err := editSubnet(context.Background(), opts, be, inst, paths)
	if err == nil {
		t.Fatal("expected an error while filter daemons are running")
	}
	want := `instance "edity" has filter daemons running (likely from a failed start); run 'abox stop edity' first`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
	if inst.Subnet != "10.10.10.0/24" {
		t.Errorf("instance subnet mutated despite live daemons: %q", inst.Subnet)
	}
}
