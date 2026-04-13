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
		wantFilter   string
	}{
		{
			name:         "simple",
			instanceName: "dev",
			wantInstance: "dev",
			wantVM:       "abox-dev",
			wantNetwork:  config.GenerateBridgeName("dev"),
			wantFilter:   "abox-dev-traffic",
		},
		{
			name:         "with-hyphen",
			instanceName: "my-instance",
			wantInstance: "my-instance",
			wantVM:       "abox-my-instance",
			wantNetwork:  config.GenerateBridgeName("my-instance"),
			wantFilter:   "abox-my-instance-traffic",
		},
		{
			name:         "with-underscore",
			instanceName: "my_instance",
			wantInstance: "my_instance",
			wantVM:       "abox-my_instance",
			wantNetwork:  config.GenerateBridgeName("my_instance"),
			wantFilter:   "abox-my_instance-traffic",
		},
		{
			name:         "with-numbers",
			instanceName: "dev123",
			wantInstance: "dev123",
			wantVM:       "abox-dev123",
			wantNetwork:  config.GenerateBridgeName("dev123"),
			wantFilter:   "abox-dev123-traffic",
		},
		{
			name:         "long-name",
			instanceName: "very-long-instance-name-for-testing",
			wantInstance: "very-long-instance-name-for-testing",
			wantVM:       "abox-very-long-instance-name-for-testing",
			wantNetwork:  config.GenerateBridgeName("very-long-instance-name-for-testing"),
			wantFilter:   "abox-very-long-instance-name-for-testing-traffic",
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
			if names.Filter != tt.wantFilter {
				t.Errorf("ResourceNames(%q).Filter = %q, want %q", tt.instanceName, names.Filter, tt.wantFilter)
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
	if got := b.StorageDir(); got != config.LibvirtImagesDir {
		t.Errorf("StorageDir() = %q, want %q", got, config.LibvirtImagesDir)
	}
}
