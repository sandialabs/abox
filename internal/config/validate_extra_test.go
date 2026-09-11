package config

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestValidateStorageDir(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		wantErr bool
	}{
		{"empty (default)", "", false},
		{"absolute clean", "/var/lib/libvirt/images/abox", false},
		{"user storage", "/home/user/.local/share/abox/disks", false},
		{"relative", "abox/disks", true},
		{"traversal", "/home/user/../../etc", true},
		{"trailing slash (benign)", "/var/lib/abox/", false},
		{"dot segment (benign)", "/var/lib/./abox", false},
		{"embedded traversal", "/var/lib/abox/../../etc", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateStorageDir(tt.dir); (err != nil) != tt.wantErr {
				t.Errorf("validateStorageDir(%q) error = %v, wantErr %v", tt.dir, err, tt.wantErr)
			}
		})
	}
}

func TestIsLegacyStorage(t *testing.T) {
	tests := []struct {
		name       string
		storageDir string
		disk       string
		want       bool
	}{
		{
			name:       "storage_dir is legacy root-owned dir",
			storageDir: LibvirtImagesDir,
			disk:       "/home/user/.local/share/abox/disks/instances/dev/disk.qcow2",
			want:       true,
		},
		{
			name:       "disk path under legacy dir",
			storageDir: "",
			disk:       LibvirtImagesDir + "/instances/dev/disk.qcow2",
			want:       true,
		},
		{
			name:       "user-owned storage and disk",
			storageDir: "/home/user/.local/share/abox/disks",
			disk:       "/home/user/.local/share/abox/disks/instances/dev/disk.qcow2",
			want:       false,
		},
		{
			name:       "empty storage and non-legacy disk",
			storageDir: "",
			disk:       "/srv/abox/disks/instances/dev/disk.qcow2",
			want:       false,
		},
		{
			// The current default: a per-user subdir LibvirtImagesDir/<uid>. It
			// shares the LibvirtImagesDir prefix but is explicitly NOT legacy.
			name:       "per-user storage_dir is not legacy",
			storageDir: LibvirtStorageDir(),
			disk:       filepath.Join(LibvirtStorageDir(), "instances", "dev", "disk.qcow2"),
			want:       false,
		},
		{
			// Disk under the per-user subtree (empty storage_dir) is also not legacy.
			name:       "disk under per-user subtree is not legacy",
			storageDir: "",
			disk:       filepath.Join(LibvirtStorageDir(), "instances", "dev", "disk.qcow2"),
			want:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst := &Instance{StorageDir: tt.storageDir}
			paths := &Paths{Disk: tt.disk}
			if got := IsLegacyStorage(inst, paths); got != tt.want {
				t.Errorf("IsLegacyStorage() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestLibvirtStorageDir verifies the per-user root shape:
// <LibvirtImagesDir>/<uid>, keyed on the NUMERIC uid so the client and the
// privilege helper (which derives it from the socket peer uid) compute the same
// path. It uses os.Getuid(), which is a Linux/unix concept.
func TestLibvirtStorageDir(t *testing.T) {
	got := LibvirtStorageDir()
	want := filepath.Join(LibvirtImagesDir, strconv.Itoa(os.Getuid()))
	if got != want {
		t.Errorf("LibvirtStorageDir() = %q, want %q", got, want)
	}
}

func TestUserStorageDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_DATA_HOME", tmp)

	got := UserStorageDir()
	want := filepath.Join(tmp, "abox", "disks")
	if got != want {
		t.Errorf("UserStorageDir() = %q, want %q", got, want)
	}
}
