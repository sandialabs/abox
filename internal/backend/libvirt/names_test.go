//go:build linux

package libvirt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/virsh"
)

// legacyInstance returns an instance on the LEGACY naming scheme (name-only
// bridge), saved to a temp XDG store so UpgradeResourceNames can commit the new
// identity through config.Save.
func legacyInstance(t *testing.T) (*config.Instance, *config.Paths) {
	t.Helper()
	paths := testPaths(t) // sets XDG_DATA_HOME to a temp dir
	inst := fullInstance()
	inst.Bridge = "abox-dev"
	if err := config.EnsureDirs(paths); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	if err := config.Save(inst, paths); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return inst, paths
}

// upgradeMockOpts scripts the upgrade-relevant virsh state: whether the legacy
// domain runs, what disk its XML names (ownership probe), whether it carries
// snapshot metadata, what subnet the legacy network declares (ownership probe),
// and injected teardown failures.
type upgradeMockOpts struct {
	running      bool
	diskPath     string // domain <disk> source; "" renders a diskless domain
	hasSnapshots bool
	netGateway   string // network <ip address>; "" renders an <ip>-less network
	listErr      error  // injected domain/network listing failure (existence probes)
	dumpxmlErr   error  // injected dumpxml failure (ownership probe)
	undefineErr  error
	netUndefErr  error
}

// upgradeMock scripts virsh for an upgrade run: the legacy domain, network, and
// nwfilter all exist, shaped by opts.
func upgradeMock(t *testing.T, o upgradeMockOpts) *virsh.MockCommander {
	t.Helper()
	return installMock(t, func(name string, args ...string) (string, error) {
		if len(args) < 3 {
			return "", nil
		}
		switch args[2] {
		case "domstate":
			if o.running {
				return "running\n", nil
			}
			return "shut off\n", nil
		case "list": // domain existence (list --all --name)
			return "abox-dev\n", o.listErr
		case "net-list":
			return "abox-dev\n", o.listErr
		case "nwfilter-list":
			return "abcd-1234  abox-dev-traffic\n", nil
		case "nwfilter-dumpxml":
			return "<filter name='abox-dev-traffic'><uuid>abcd-1234</uuid></filter>", nil
		case "dumpxml":
			if o.dumpxmlErr != nil {
				return "", o.dumpxmlErr
			}
			disk := ""
			if o.diskPath != "" {
				disk = fmt.Sprintf("<disk type='file' device='disk'><source file='%s'/></disk>", o.diskPath)
			}
			return fmt.Sprintf("<domain><name>abox-dev</name><devices>%s</devices></domain>", disk), nil
		case "snapshot-list":
			if o.hasSnapshots {
				return "snap1\n", nil
			}
			return "", nil
		case "net-dumpxml":
			if o.netGateway == "" {
				return "<network><name>abox-dev</name></network>", nil
			}
			return fmt.Sprintf("<network><name>abox-dev</name><ip address='%s' netmask='255.255.255.0'/></network>", o.netGateway), nil
		case "undefine":
			return "", o.undefineErr
		case "net-undefine":
			return "", o.netUndefErr
		}
		return "", nil
	}, nil)
}

// ownedUpgradeMock is upgradeMock for the common case: a stopped legacy domain
// whose disk and network subnet both belong to the instance under test.
func ownedUpgradeMock(t *testing.T, paths *config.Paths) *virsh.MockCommander {
	t.Helper()
	return upgradeMock(t, upgradeMockOpts{diskPath: paths.Disk, netGateway: "10.10.10.1"})
}

// TestUpgradeResourceNames: a legacy-named instance is upgraded in place — old
// domain undefined KEEPING storage, old network and nwfilter removed, host
// egress rules flushed for the old bridge, and the per-user bridge committed to
// config.
func TestUpgradeResourceNames(t *testing.T) {
	inst, paths := legacyInstance(t)
	mock := ownedUpgradeMock(t, paths)

	f := &fakeEnforcer{}
	b := New().(*Backend)
	b.egress = newControllerWithEnforcer(f)

	upgraded, err := b.UpgradeResourceNames(context.Background(), inst, paths)
	if err != nil {
		t.Fatalf("UpgradeResourceNames: %v", err)
	}
	if !upgraded {
		t.Fatal("UpgradeResourceNames = false, want true for a legacy instance")
	}

	// Host egress rules flushed for the OLD bridge.
	if !f.removeCalled || f.removeBridge != "abox-dev" {
		t.Errorf("enforcer.Remove bridge = %q (called=%v), want abox-dev", f.removeBridge, f.removeCalled)
	}

	// Old-named objects torn down; the domain undefine must keep storage.
	undef := findCall(mock.Calls, "undefine")
	if undef == nil || !slices.Contains(undef.Args, "abox-dev") {
		t.Fatalf("expected undefine of abox-dev; calls=%+v", mock.Calls)
	}
	if slices.Contains(undef.Args, "--remove-all-storage") {
		t.Errorf("domain undefine must keep storage; args=%v", undef.Args)
	}
	for _, want := range []string{"net-undefine", "nwfilter-undefine"} {
		if findCall(mock.Calls, want) == nil {
			t.Errorf("expected %s of the legacy objects; calls=%+v", want, mock.Calls)
		}
	}

	// The per-user identity is committed: in memory and on disk.
	wantBridge := config.GenerateBridgeName(os.Getuid(), "dev")
	if inst.Bridge != wantBridge {
		t.Errorf("inst.Bridge = %q, want %q", inst.Bridge, wantBridge)
	}
	reloaded, _, err := config.Load("dev")
	if err != nil {
		t.Fatalf("Load after upgrade: %v", err)
	}
	if reloaded.Bridge != wantBridge {
		t.Errorf("persisted bridge = %q, want %q", reloaded.Bridge, wantBridge)
	}
	if !reloaded.UsesCurrentNames() {
		t.Error("instance should be on the current naming scheme after upgrade")
	}
}

// TestUpgradeResourceNames_NoopWhenCurrent: an instance already on the per-user
// scheme is left alone — no teardown, no save.
func TestUpgradeResourceNames_NoopWhenCurrent(t *testing.T) {
	paths := testPaths(t)
	inst := fullInstance() // fullInstance records the per-user bridge
	mock := installMock(t, nil, nil)

	b := New().(*Backend)
	upgraded, err := b.UpgradeResourceNames(context.Background(), inst, paths)
	if err != nil {
		t.Fatalf("UpgradeResourceNames: %v", err)
	}
	if upgraded {
		t.Error("UpgradeResourceNames = true, want false for a current-scheme instance")
	}
	if len(mock.Calls) != 0 {
		t.Errorf("no virsh calls expected for a no-op upgrade; got %+v", mock.Calls)
	}
}

// TestUpgradeResourceNames_RefusesRunningVM: a legacy instance whose old-named
// VM is still running must not be renamed out from under it.
func TestUpgradeResourceNames_RefusesRunningVM(t *testing.T) {
	inst, paths := legacyInstance(t)
	upgradeMock(t, upgradeMockOpts{running: true, diskPath: paths.Disk, netGateway: "10.10.10.1"})

	b := New().(*Backend)
	if _, err := b.UpgradeResourceNames(context.Background(), inst, paths); err == nil {
		t.Fatal("UpgradeResourceNames should refuse while the legacy-named VM is running")
	}
	// The legacy identity must remain committed on disk.
	reloaded, _, err := config.Load("dev")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if reloaded.Bridge != "abox-dev" {
		t.Errorf("bridge = %q, want unchanged abox-dev", reloaded.Bridge)
	}
}

// assertLegacyOnDisk fails unless the persisted config still records the legacy
// bridge — i.e. a failed upgrade committed nothing and will retry cleanly.
func assertLegacyOnDisk(t *testing.T) {
	t.Helper()
	reloaded, _, err := config.Load("dev")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if reloaded.Bridge != "abox-dev" {
		t.Errorf("persisted bridge = %q, want unchanged abox-dev (no commit on failure)", reloaded.Bridge)
	}
}

// TestUpgradeResourceNames_SkipsUnownedObjects: legacy names derive from the
// instance name alone, so a same-named domain/network on a shared host may be
// ANOTHER USER'S. Objects that don't match this instance's disk/subnet are left
// alone — but the upgrade still commits, since nothing of ours lives under them.
func TestUpgradeResourceNames_SkipsUnownedObjects(t *testing.T) {
	inst, paths := legacyInstance(t)
	// Domain uses someone else's disk; network declares someone else's subnet.
	mock := upgradeMock(t, upgradeMockOpts{diskPath: "/other/user/disk.qcow2", netGateway: "10.10.99.1"})

	f := &fakeEnforcer{}
	b := New().(*Backend)
	b.egress = newControllerWithEnforcer(f)
	upgraded, err := b.UpgradeResourceNames(context.Background(), inst, paths)
	if err != nil {
		t.Fatalf("UpgradeResourceNames: %v", err)
	}
	if !upgraded {
		t.Fatal("UpgradeResourceNames = false, want true (commit happens despite skipped teardown)")
	}
	if findCall(mock.Calls, "undefine") != nil {
		t.Errorf("must not undefine another user's same-named domain; calls=%+v", mock.Calls)
	}
	if findCall(mock.Calls, "net-undefine") != nil {
		t.Errorf("must not delete another user's same-named network; calls=%+v", mock.Calls)
	}
	if f.removeCalled {
		t.Error("must not flush host egress rules keyed on another user's bridge")
	}
	if want := config.GenerateBridgeName(os.Getuid(), "dev"); inst.Bridge != want {
		t.Errorf("inst.Bridge = %q, want committed per-user bridge %q", inst.Bridge, want)
	}
}

// TestUpgradeResourceNames_RefusesSnapshots: libvirt snapshot metadata does not
// survive the undefine/redefine rename, so an owned domain that carries
// snapshots fails the upgrade with guidance instead of silently orphaning them.
func TestUpgradeResourceNames_RefusesSnapshots(t *testing.T) {
	inst, paths := legacyInstance(t)
	mock := upgradeMock(t, upgradeMockOpts{diskPath: paths.Disk, netGateway: "10.10.10.1", hasSnapshots: true})

	b := New().(*Backend)
	b.egress = newControllerWithEnforcer(&fakeEnforcer{})
	_, err := b.UpgradeResourceNames(context.Background(), inst, paths)
	if err == nil || !strings.Contains(err.Error(), "snapshot") {
		t.Fatalf("UpgradeResourceNames = %v, want snapshot refusal", err)
	}
	if findCall(mock.Calls, "undefine") != nil {
		t.Errorf("no teardown may run once snapshots are detected; calls=%+v", mock.Calls)
	}
	assertLegacyOnDisk(t)
}

// TestUpgradeResourceNames_AbortsOnOwnedTeardownFailure: committing the new
// identity over a failed teardown of an OWNED object would leave a same-disk
// domain (or a subnet-claiming network) defined under the old name, wedging
// every subsequent start — so the upgrade must fail without committing.
func TestUpgradeResourceNames_AbortsOnOwnedTeardownFailure(t *testing.T) {
	t.Run("domain undefine fails", func(t *testing.T) {
		inst, paths := legacyInstance(t)
		upgradeMock(t, upgradeMockOpts{diskPath: paths.Disk, netGateway: "10.10.10.1",
			undefineErr: errors.New("boom")})

		b := New().(*Backend)
		b.egress = newControllerWithEnforcer(&fakeEnforcer{})
		if _, err := b.UpgradeResourceNames(context.Background(), inst, paths); err == nil {
			t.Fatal("UpgradeResourceNames should fail when the owned domain undefine fails")
		}
		assertLegacyOnDisk(t)
	})

	t.Run("network delete fails", func(t *testing.T) {
		inst, paths := legacyInstance(t)
		upgradeMock(t, upgradeMockOpts{diskPath: paths.Disk, netGateway: "10.10.10.1",
			netUndefErr: errors.New("boom")})

		b := New().(*Backend)
		b.egress = newControllerWithEnforcer(&fakeEnforcer{})
		if _, err := b.UpgradeResourceNames(context.Background(), inst, paths); err == nil {
			t.Fatal("UpgradeResourceNames should fail when the owned network delete fails")
		}
		assertLegacyOnDisk(t)
	})

	t.Run("existence probe fails", func(t *testing.T) {
		// A transient `virsh list` failure must abort too: treating an owned
		// legacy domain as ABSENT and committing is the same two-domains-one-
		// qcow2 corruption as treating it as foreign.
		inst, paths := legacyInstance(t)
		upgradeMock(t, upgradeMockOpts{diskPath: paths.Disk, netGateway: "10.10.10.1",
			listErr: errors.New("libvirtd restarting")})

		b := New().(*Backend)
		b.egress = newControllerWithEnforcer(&fakeEnforcer{})
		if _, err := b.UpgradeResourceNames(context.Background(), inst, paths); err == nil {
			t.Fatal("UpgradeResourceNames should fail when the existence probe fails")
		}
		assertLegacyOnDisk(t)
	})

	t.Run("ownership probe fails", func(t *testing.T) {
		// A transient dumpxml failure must abort (fail closed), NOT treat the
		// existing same-named domain as foreign/absent and commit over it —
		// that would leave two domains sharing one qcow2.
		inst, paths := legacyInstance(t)
		mock := upgradeMock(t, upgradeMockOpts{diskPath: paths.Disk, netGateway: "10.10.10.1",
			dumpxmlErr: errors.New("libvirtd restarting")})

		b := New().(*Backend)
		b.egress = newControllerWithEnforcer(&fakeEnforcer{})
		if _, err := b.UpgradeResourceNames(context.Background(), inst, paths); err == nil {
			t.Fatal("UpgradeResourceNames should fail when the ownership probe fails")
		}
		if findCall(mock.Calls, "undefine") != nil {
			t.Errorf("no teardown may run on an unverified domain; calls=%+v", mock.Calls)
		}
		assertLegacyOnDisk(t)
	})
}

// TestUpgradeResourceNames_CopiedDirLeavesForeignBridgeAlone: UsesCurrentNames
// is false for a COPIED instance dir too (bridge recorded under another uid).
// That bridge names the original owner's CURRENT per-user network, and the
// copied config carries their subnet — so the subnet ownership probe alone
// would pass. The upgrade must only ever tear down a network under this
// instance's own legacy derivation; anything else is skipped (rules flush
// included) while the per-user identity still commits.
func TestUpgradeResourceNames_CopiedDirLeavesForeignBridgeAlone(t *testing.T) {
	inst, paths := legacyInstance(t)
	inst.Bridge = config.GenerateBridgeName(99999, "dev") // another uid's abx- bridge
	if err := config.Save(inst, paths); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// The mock would happily report the network as existing and declaring this
	// subnet — the name gate must prevent it from ever being consulted.
	mock := upgradeMock(t, upgradeMockOpts{diskPath: paths.Disk, netGateway: "10.10.10.1"})

	f := &fakeEnforcer{}
	b := New().(*Backend)
	b.egress = newControllerWithEnforcer(f)
	upgraded, err := b.UpgradeResourceNames(context.Background(), inst, paths)
	if err != nil {
		t.Fatalf("UpgradeResourceNames: %v", err)
	}
	if !upgraded {
		t.Fatal("UpgradeResourceNames = false, want true (commit happens; foreign objects skipped)")
	}
	if findCall(mock.Calls, "net-undefine") != nil || findCall(mock.Calls, "net-destroy") != nil {
		t.Errorf("must not touch another user's per-user network; calls=%+v", mock.Calls)
	}
	if f.removeCalled {
		t.Error("must not flush host egress rules keyed on another user's bridge")
	}
	if want := config.GenerateBridgeName(os.Getuid(), "dev"); inst.Bridge != want {
		t.Errorf("inst.Bridge = %q, want committed per-user bridge %q", inst.Bridge, want)
	}
}

// TestVMRemove_LegacyOwnershipGate: `abox remove` of a legacy-named instance
// destroys the domain WITH its storage, so the same disk-ownership gate the
// upgrade uses must protect it from a same-named domain owned by another user.
func TestVMRemove_LegacyOwnershipGate(t *testing.T) {
	t.Run("unowned legacy domain left alone", func(t *testing.T) {
		legacyInstance(t)
		mock := upgradeMock(t, upgradeMockOpts{diskPath: "/other/user/disk.qcow2"})
		m := &VMManager{}
		if err := m.Remove(context.Background(), "dev"); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		if findCall(mock.Calls, "undefine") != nil {
			t.Errorf("must not undefine (let alone --remove-all-storage) another user's domain; calls=%+v", mock.Calls)
		}
	})

	t.Run("owned legacy domain removed", func(t *testing.T) {
		_, paths := legacyInstance(t)
		mock := upgradeMock(t, upgradeMockOpts{diskPath: paths.Disk})
		m := &VMManager{}
		if err := m.Remove(context.Background(), "dev"); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		undef := findCall(mock.Calls, "undefine")
		if undef == nil || !slices.Contains(undef.Args, "--remove-all-storage") {
			t.Fatalf("expected undefine --remove-all-storage of the owned legacy domain; calls=%+v", mock.Calls)
		}
	})

	t.Run("probe failure aborts", func(t *testing.T) {
		legacyInstance(t)
		mock := upgradeMock(t, upgradeMockOpts{dumpxmlErr: errors.New("libvirtd restarting")})
		m := &VMManager{}
		if err := m.Remove(context.Background(), "dev"); err == nil {
			t.Fatal("Remove should fail closed when ownership cannot be verified")
		}
		if findCall(mock.Calls, "undefine") != nil {
			t.Errorf("no undefine may run on an unverified domain; calls=%+v", mock.Calls)
		}
	})

	t.Run("existence probe failure aborts", func(t *testing.T) {
		// `virsh list` erroring must not read as "absent" — that would skip the
		// ownership gate entirely and fall through to --remove-all-storage.
		legacyInstance(t)
		mock := upgradeMock(t, upgradeMockOpts{listErr: errors.New("libvirtd restarting")})
		m := &VMManager{}
		if err := m.Remove(context.Background(), "dev"); err == nil {
			t.Fatal("Remove should fail closed when the existence probe fails")
		}
		if findCall(mock.Calls, "undefine") != nil {
			t.Errorf("no undefine may run when existence is unverifiable; calls=%+v", mock.Calls)
		}
	})
}
