//go:build linux

package libvirt

import (
	"os"
	"testing"

	"github.com/sandialabs/abox/internal/config"
)

func TestResourceNames(t *testing.T) {
	b := &Backend{}
	uid := os.Getuid()

	// ResourceNames describes a NEW instance: per-user domain and bridge, so two
	// users' same-named instances never collide on the shared libvirtd/interface
	// namespaces.
	for _, instanceName := range []string{
		"dev",
		"my-instance",
		"my_instance",
		"dev123",
		"very-long-instance-name-for-testing",
	} {
		t.Run(instanceName, func(t *testing.T) {
			names := b.ResourceNames(instanceName)

			if names.Instance != instanceName {
				t.Errorf("ResourceNames(%q).Instance = %q, want %q", instanceName, names.Instance, instanceName)
			}
			if want := config.DomainNameFor(uid, instanceName); names.VM != want {
				t.Errorf("ResourceNames(%q).VM = %q, want %q", instanceName, names.VM, want)
			}
			if want := config.GenerateBridgeName(uid, instanceName); names.Network != want {
				t.Errorf("ResourceNames(%q).Network = %q, want %q", instanceName, names.Network, want)
			}
		})
	}
}

func TestResourceNames_Consistency(t *testing.T) {
	b := &Backend{}
	name := "test-instance"
	names1 := b.ResourceNames(name)
	names2 := b.ResourceNames(name)

	if names1 != names2 {
		t.Errorf("ResourceNames(%q) is not deterministic: %v != %v", name, names1, names2)
	}
}

func TestStorageDir(t *testing.T) {
	b := &Backend{}
	if got := b.StorageDir(); got != config.LibvirtStorageDir() {
		t.Errorf("StorageDir() = %q, want %q", got, config.LibvirtStorageDir())
	}
}

func TestRequiredTools(t *testing.T) {
	b := &Backend{}
	got := make(map[string]bool)
	for _, tool := range b.RequiredTools() {
		got[tool.Name] = true
	}
	// virsh is required; ACL tooling (setfacl) is no longer needed since the QEMU
	// process reaches images via group ownership of the setgid storage root.
	if !got["virsh"] {
		t.Errorf("RequiredTools() missing %q; got %v", "virsh", got)
	}
	if got["setfacl"] {
		t.Errorf("RequiredTools() should no longer require setfacl; got %v", got)
	}
}

func TestMonitorTransport(t *testing.T) {
	b := &Backend{}
	mt := b.MonitorTransport()
	if mt == nil {
		t.Fatal("MonitorTransport() = nil, want non-nil")
	}
	if got, want := mt.GuestDevice(), "/dev/virtio-ports/abox.monitor.0"; got != want {
		t.Errorf("GuestDevice() = %q, want %q", got, want)
	}
}
