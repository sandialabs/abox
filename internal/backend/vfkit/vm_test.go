//go:build darwin

package vfkit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sandialabs/abox/internal/backend/backendtest"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/vfkit"
	"github.com/sandialabs/abox/internal/vmnethelper"
)

func TestDeriveVMNetAddresses(t *testing.T) {
	tests := []struct {
		name      string
		subnet    string
		gateway   string
		wantMask  string
		wantEnd   string
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "valid /24",
			subnet:   "192.168.64.0/24",
			gateway:  "192.168.64.1",
			wantMask: "255.255.255.0",
			// broadcast is .255, end = broadcast-1 = .254
			wantEnd: "192.168.64.254",
		},
		{
			name:     "valid /30 boundary",
			subnet:   "10.0.0.0/30",
			gateway:  "10.0.0.1",
			wantMask: "255.255.255.252",
			// hostMask=3, broadcast=.3, end=.2
			wantEnd: "10.0.0.2",
		},
		{
			name:      "reject /31 (hostMask 1 < 3)",
			subnet:    "10.0.0.0/31",
			gateway:   "10.0.0.1",
			wantErr:   true,
			errSubstr: "too small",
		},
		{
			name:      "reject /32 (hostMask 0 < 3)",
			subnet:    "10.0.0.0/32",
			gateway:   "10.0.0.0",
			wantErr:   true,
			errSubstr: "too small",
		},
		{
			name:      "reject non-IPv4 CIDR",
			subnet:    "fd00::/64",
			gateway:   "fd00::1",
			wantErr:   true,
			errSubstr: "not IPv4",
		},
		{
			name:      "reject unparseable CIDR",
			subnet:    "not-a-cidr",
			gateway:   "10.0.0.1",
			wantErr:   true,
			errSubstr: "parse subnet",
		},
		{
			name:      "reject invalid gateway",
			subnet:    "192.168.64.0/24",
			gateway:   "not-an-ip",
			wantErr:   true,
			errSubstr: "invalid IPv4 gateway",
		},
		{
			name:      "reject gateway == network address",
			subnet:    "192.168.64.0/24",
			gateway:   "192.168.64.0",
			wantErr:   true,
			errSubstr: "not a usable host",
		},
		{
			name:      "reject gateway == end address",
			subnet:    "192.168.64.0/24",
			gateway:   "192.168.64.254", // gwNum >= endNum
			wantErr:   true,
			errSubstr: "not a usable host",
		},
		{
			name:      "reject gateway == broadcast address",
			subnet:    "192.168.64.0/24",
			gateway:   "192.168.64.255",
			wantErr:   true,
			errSubstr: "not a usable host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mask, end, err := deriveVMNetAddresses(tt.subnet, tt.gateway)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got mask=%q end=%q", mask, end)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if mask != tt.wantMask {
				t.Errorf("mask = %q, want %q", mask, tt.wantMask)
			}
			if end != tt.wantEnd {
				t.Errorf("end = %q, want %q", end, tt.wantEnd)
			}
		})
	}
}

func TestRestfulURI(t *testing.T) {
	tests := []struct {
		name string
		port int
		want string
	}{
		{name: "zero port yields empty", port: 0, want: ""},
		{name: "non-zero port yields 127.0.0.1 URI", port: 51234, want: "tcp://127.0.0.1:51234"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst := &config.Instance{
				BackendConfig: map[string]any{
					config.BackendKeyRESTPort: tt.port,
				},
			}
			if got := restfulURI(inst); got != tt.want {
				t.Errorf("restfulURI() = %q, want %q", got, tt.want)
			}
		})
	}
}

// uuidV4Re matches the canonical 8-4-4-4-12 hex layout with version nibble 4
// and variant nibble in {8,9,a,b}.
var uuidV4Re = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestGenerateUUID(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		got, err := generateUUID()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !uuidV4Re.MatchString(got) {
			t.Fatalf("uuid %q is not a valid v4 UUID (wrong layout/version/variant)", got)
		}
		// Explicit version + variant assertions on the raw nibbles.
		if got[14] != '4' {
			t.Errorf("uuid %q version nibble = %c, want 4", got, got[14])
		}
		variant := got[19]
		if variant != '8' && variant != '9' && variant != 'a' && variant != 'b' {
			t.Errorf("uuid %q variant nibble = %c, want one of 8,9,a,b", got, variant)
		}
		if seen[got] {
			t.Errorf("generateUUID produced a duplicate: %q", got)
		}
		seen[got] = true
	}
}

// TestResolvePIDFile_Primary verifies that when a PID file exists in the
// per-instance run dir, resolvePIDFile returns that primary path.
func TestResolvePIDFile_Primary(t *testing.T) {
	dataHome := t.TempDir()
	runtimeDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	const name = "alpha"
	const component = "vfkit"
	base := pidFileName(name, component)

	// The primary path is <run dir>/<base>; instanceRunDir creates the dir.
	primaryDir := instanceRunDir(name)
	primary := filepath.Join(primaryDir, base)
	writeFile(t, primary)

	if got := resolvePIDFile(name, component); got != primary {
		t.Errorf("resolvePIDFile() = %q, want primary %q", got, primary)
	}
}

// TestResolvePIDFile_LegacyFallback verifies that when the primary file is
// absent but a legacy $XDG_RUNTIME_DIR file exists, the legacy path is returned.
func TestResolvePIDFile_LegacyFallback(t *testing.T) {
	dataHome := t.TempDir()
	runtimeDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	const name = "beta"
	const component = "vmnethelper"
	base := pidFileName(name, component)

	// legacyPIDDir resolves to XDG_RUNTIME_DIR (it exists), not os.TempDir().
	legacyDir := legacyPIDDir()
	if legacyDir != runtimeDir {
		t.Fatalf("legacyPIDDir() = %q, want %q (the runtime dir)", legacyDir, runtimeDir)
	}
	legacy := filepath.Join(legacyDir, base)
	writeFile(t, legacy)

	// Ensure the primary does NOT exist: instanceRunDir differs from legacyDir.
	primaryDir := instanceRunDir(name)
	if primaryDir == legacyDir {
		t.Fatalf("primary dir %q unexpectedly equals legacy dir", primaryDir)
	}

	if got := resolvePIDFile(name, component); got != legacy {
		t.Errorf("resolvePIDFile() = %q, want legacy %q", got, legacy)
	}
}

// TestResolvePIDFile_DefaultsToPrimary verifies that when neither file exists,
// the primary path is returned (new writers use it).
func TestResolvePIDFile_DefaultsToPrimary(t *testing.T) {
	dataHome := t.TempDir()
	runtimeDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	const name = "gamma"
	const component = "vfkit"
	base := pidFileName(name, component)

	primary := filepath.Join(instanceRunDir(name), base)
	if got := resolvePIDFile(name, component); got != primary {
		t.Errorf("resolvePIDFile() = %q, want primary %q", got, primary)
	}
}

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("12345\n"), 0o600); err != nil {
		t.Fatalf("failed to write %q: %v", path, err)
	}
}

// startTestInstance is the instance used by the Start fail-closed tests. Its
// subnet/gateway are valid for deriveVMNetAddresses and the gateway matches the
// fake helper's returned StartAddress so the determinism guard passes.
func startTestInstance() *config.Instance {
	return &config.Instance{
		Version:    config.CurrentInstanceVersion,
		Name:       "startvm",
		Base:       "ubuntu-24.04",
		CPUs:       2,
		Memory:     4096,
		Subnet:     "192.168.64.0/24",
		Gateway:    "192.168.64.1",
		IPAddress:  "192.168.64.10",
		MACAddress: "00:0c:29:ab:cd:ef",
	}
}

// setupStartInstance persists a default-storage instance config under a temp
// abox data dir (so loadInstanceState/config.Load succeed) and points
// vmnet-helper resolution at a dummy binary so ResolveBinaryPath succeeds
// without a real install. Start looks the instance up by name, so nothing needs
// to be returned.
func setupStartInstance(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", backendtest.ShortDataHome(t))

	// ResolveBinaryPath honors ABOX_VMNET_HELPER_PATH; point it at a real file so
	// Start gets past binary resolution without a Homebrew install.
	dummyBin := filepath.Join(t.TempDir(), "vmnet-helper")
	writeFile(t, dummyBin)
	t.Setenv("ABOX_VMNET_HELPER_PATH", dummyBin)

	inst := startTestInstance()
	paths, err := config.GetPaths(inst.Name)
	if err != nil {
		t.Fatalf("GetPaths: %v", err)
	}
	if err := config.EnsureDirs(paths); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	if err := config.Save(inst, paths); err != nil {
		t.Fatalf("Save: %v", err)
	}
}

// stubStartSeams replaces every process-spawning + config-save seam Start uses
// with hermetic fakes, restoring them on cleanup. The helper fake creates the
// vmnet socket file (so waitForSocket returns immediately) and reports the
// instance's gateway (so the determinism guard passes). Callers override
// individual return values via the returned trackers.
type startSeamTrackers struct {
	forceStopVMCalled   bool
	helperForceStopSeen bool
	savedBridge         bool
}

func stubStartSeams(t *testing.T, verifyErr, saveErr error) *startSeamTrackers {
	t.Helper()
	origStartVM, origVerify, origForceVM := startVMFn, verifyLiveFn, forceStopVMFn
	origHelperStart, origHelperForce, origSave := helperStartFn, helperForceStopFn, saveConfigFn
	t.Cleanup(func() {
		startVMFn, verifyLiveFn, forceStopVMFn = origStartVM, origVerify, origForceVM
		helperStartFn, helperForceStopFn, saveConfigFn = origHelperStart, origHelperForce, origSave
	})

	tr := &startSeamTrackers{}

	helperStartFn = func(cfg vmnethelper.HelperConfig) (*vmnethelper.StartResult, error) {
		// vfkit connects to this socket; Start's waitForSocket blocks on its
		// existence, so the real helper's bind is faked by touching the file.
		writeFile(t, cfg.SocketPath)
		return &vmnethelper.StartResult{
			PID:             4242,
			StartAddress:    "192.168.64.1",
			BridgeInterface: "bridge101",
		}, nil
	}
	startVMFn = func(cfg vfkit.VMConfig) (int, error) { return 1234, nil }
	verifyLiveFn = func(pidFile, restfulURI string, grace time.Duration) error { return verifyErr }
	forceStopVMFn = func(pidFile string) error { tr.forceStopVMCalled = true; return nil }
	helperForceStopFn = func(pidFile string) error { tr.helperForceStopSeen = true; return nil }
	saveConfigFn = func(inst *config.Instance, paths *config.Paths) error {
		if _, ok := inst.BackendConfig[config.BackendKeyBridge]; ok {
			tr.savedBridge = true
		}
		return saveErr
	}
	return tr
}

// TestStart_VerifyLiveFailureTearsDown covers the F13 fail-closed branch: when
// vfkit dies immediately (VerifyLive errors), Start must force-stop both vfkit
// and the vmnet-helper and return an error, so an instantly-dead VM never leaves
// a live root helper + bridge orphaned.
func TestStart_VerifyLiveFailureTearsDown(t *testing.T) {
	setupStartInstance(t)
	tr := stubStartSeams(t, errors.New("vfkit died at boot"), nil)

	m := &VMManager{}
	err := m.Start(context.Background(), "startvm")
	if err == nil {
		t.Fatal("expected Start to return an error when VerifyLive fails")
	}
	if !tr.forceStopVMCalled {
		t.Error("vfkit was not force-stopped after VerifyLive failure (VM left running)")
	}
	if !tr.helperForceStopSeen {
		t.Error("vmnet-helper was not force-stopped after VerifyLive failure (helper + bridge orphaned)")
	}
}

// TestStart_BridgeSaveFailureTearsDown covers the F11 fail-closed branch: when
// persisting the bridge key fails, Start must force-stop both processes and
// return an error, because without the persisted bridge the post-boot pf ruleset
// can never load — a running guest with zero egress filtering.
func TestStart_BridgeSaveFailureTearsDown(t *testing.T) {
	setupStartInstance(t)
	tr := stubStartSeams(t, nil, errors.New("disk full"))

	m := &VMManager{}
	err := m.Start(context.Background(), "startvm")
	if err == nil {
		t.Fatal("expected Start to return an error when saving the bridge key fails")
	}
	if !tr.forceStopVMCalled {
		t.Error("vfkit was not force-stopped after bridge-save failure (VM left running unfiltered)")
	}
	if !tr.helperForceStopSeen {
		t.Error("vmnet-helper was not force-stopped after bridge-save failure (helper + bridge orphaned)")
	}
}

// TestStart_HappyPath verifies the success path leaves both processes running
// (no force-stop) and persists the resolved bridge for post-boot pf scoping.
func TestStart_HappyPath(t *testing.T) {
	setupStartInstance(t)
	tr := stubStartSeams(t, nil, nil)

	m := &VMManager{}
	if err := m.Start(context.Background(), "startvm"); err != nil {
		t.Fatalf("unexpected error on happy path: %v", err)
	}
	if tr.forceStopVMCalled {
		t.Error("vfkit was force-stopped on the happy path")
	}
	if tr.helperForceStopSeen {
		t.Error("vmnet-helper was force-stopped on the happy path")
	}
	if !tr.savedBridge {
		t.Error("bridge interface was not persisted (post-boot pf ruleset could not scope)")
	}
}
