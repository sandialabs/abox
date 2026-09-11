//go:build linux

package libvirt

import (
	"testing"

	"github.com/sandialabs/abox/internal/config"
)

func TestResourceNames(t *testing.T) {
	b := &Backend{}

	tests := []struct {
		name         string
		instanceName string
		wantInstance string
		wantVM       string
		wantNetwork  string
	}{
		{
			name:         "simple",
			instanceName: "dev",
			wantInstance: "dev",
			wantVM:       "abox-dev",
			wantNetwork:  config.GenerateBridgeName("dev"),
		},
		{
			name:         "with-hyphen",
			instanceName: "my-instance",
			wantInstance: "my-instance",
			wantVM:       "abox-my-instance",
			wantNetwork:  config.GenerateBridgeName("my-instance"),
		},
		{
			name:         "with-underscore",
			instanceName: "my_instance",
			wantInstance: "my_instance",
			wantVM:       "abox-my_instance",
			wantNetwork:  config.GenerateBridgeName("my_instance"),
		},
		{
			name:         "with-numbers",
			instanceName: "dev123",
			wantInstance: "dev123",
			wantVM:       "abox-dev123",
			wantNetwork:  config.GenerateBridgeName("dev123"),
		},
		{
			name:         "long-name",
			instanceName: "very-long-instance-name-for-testing",
			wantInstance: "very-long-instance-name-for-testing",
			wantVM:       "abox-very-long-instance-name-for-testing",
			wantNetwork:  config.GenerateBridgeName("very-long-instance-name-for-testing"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			names := b.ResourceNames(tt.instanceName)

			if names.Instance != tt.wantInstance {
				t.Errorf("ResourceNames(%q).Instance = %q, want %q", tt.instanceName, names.Instance, tt.wantInstance)
			}
			if names.VM != tt.wantVM {
				t.Errorf("ResourceNames(%q).VM = %q, want %q", tt.instanceName, names.VM, tt.wantVM)
			}
			if names.Network != tt.wantNetwork {
				t.Errorf("ResourceNames(%q).Network = %q, want %q", tt.instanceName, names.Network, tt.wantNetwork)
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
