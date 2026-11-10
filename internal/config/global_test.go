package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeGlobalConfig points XDG_CONFIG_HOME at a temp dir and writes body as
// the global config.
func writeGlobalConfig(t *testing.T, body string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	path := filepath.Join(home, "abox", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadGlobalConfigStorageDir(t *testing.T) {
	skipOnWindows(t)
	writeGlobalConfig(t, "version: 1\nstorage_dir: /scratch/user/abox/\n")
	cfg, err := LoadGlobalConfig()
	if err != nil {
		t.Fatalf("LoadGlobalConfig: %v", err)
	}
	if cfg.StorageDir != "/scratch/user/abox" {
		t.Errorf("StorageDir = %q, want cleaned /scratch/user/abox", cfg.StorageDir)
	}
}

func TestLoadGlobalConfigRejectsBadStorageDir(t *testing.T) {
	skipOnWindows(t)
	cases := map[string]string{
		"relative":        "scratch/abox",
		"traversal":       "/scratch/../etc",
		"filesystem root": "/",
		"legacy root":     LibvirtImagesDir,
		"other uid":       filepath.Join(LibvirtImagesDir, "99999"),
	}
	for name, dir := range cases {
		t.Run(name, func(t *testing.T) {
			writeGlobalConfig(t, "version: 1\nstorage_dir: "+dir+"\n")
			_, err := LoadGlobalConfig()
			if err == nil || !strings.Contains(err.Error(), "storage_dir") {
				t.Fatalf("LoadGlobalConfig(storage_dir=%q) error = %v, want a storage_dir rejection", dir, err)
			}
		})
	}
}

func TestLoadGlobalConfigAcceptsDefaultPerUserDir(t *testing.T) {
	skipOnWindows(t)
	writeGlobalConfig(t, "version: 1\nstorage_dir: "+LibvirtStorageDir()+"\n")
	if _, err := LoadGlobalConfig(); err != nil {
		t.Fatalf("LoadGlobalConfig(default per-user dir) = %v, want nil", err)
	}
}

func TestGetPathsForNewInstance(t *testing.T) {
	skipOnWindows(t)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // no config file
	p, err := GetPathsForNewInstance("dev", "/default")
	if err != nil {
		t.Fatalf("GetPathsForNewInstance without config: %v", err)
	}
	if p.StorageDir != "/default" || p.Disk != "/default/instances/dev/disk.qcow2" {
		t.Errorf("without config: StorageDir = %q, Disk = %q, want under /default", p.StorageDir, p.Disk)
	}

	writeGlobalConfig(t, "version: 1\nstorage_dir: /scratch/abox\n")
	p, err = GetPathsForNewInstance("dev", "/default")
	if err != nil {
		t.Fatalf("GetPathsForNewInstance with config: %v", err)
	}
	if p.StorageDir != "/scratch/abox" || p.Disk != "/scratch/abox/instances/dev/disk.qcow2" {
		t.Errorf("with config: StorageDir = %q, Disk = %q, want under /scratch/abox", p.StorageDir, p.Disk)
	}

	// An invalid config must fail, never silently fall back to the default.
	writeGlobalConfig(t, "version: 1\nstorage_dir: relative\n")
	if _, err := GetPathsForNewInstance("dev", "/default"); err == nil {
		t.Error("GetPathsForNewInstance with invalid storage_dir: want error, got nil")
	}
}

func TestAllocateSubnetRejectsInvalidGlobalConfig(t *testing.T) {
	skipOnWindows(t)
	writeGlobalConfig(t, "version: 1\nstorage_dir: relative\n")
	if _, _, _, err := AllocateSubnet(""); err == nil {
		t.Error("AllocateSubnet with an invalid global config: want error, got nil")
	}
}

func TestLoadGlobalConfigRejectsBadSubnetPool(t *testing.T) {
	skipOnWindows(t)
	for _, pool := range []string{"not-a-cidr", "10.10.0.0", "fd00::/64"} {
		writeGlobalConfig(t, "version: 1\nsubnet_pool: "+pool+"\n")
		_, err := LoadGlobalConfig()
		if err == nil || !strings.Contains(err.Error(), "subnet_pool") {
			t.Errorf("LoadGlobalConfig(subnet_pool=%q) error = %v, want a subnet_pool rejection", pool, err)
		}
	}
}
