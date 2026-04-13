package images

import (
	"strings"
	"testing"
)

func TestAlmaLinuxChecksumParsing(t *testing.T) {
	// AlmaLinux uses standard checksum format: <hash>  <filename>
	// This is already handled by ParseChecksums in images.go
	input := `5ff9c048859046f41db4a33b1f1a96675711288078aac66b47d0be023af270d1  AlmaLinux-9-GenericCloud-9.7-20251118.x86_64.qcow2
5ff9c048859046f41db4a33b1f1a96675711288078aac66b47d0be023af270d1  AlmaLinux-9-GenericCloud-latest.x86_64.qcow2
67cd4104d2a7f521bd005886acde67276fb452a046f2501d0f0fe843dd39a084  AlmaLinux-9-OpenNebula-latest.x86_64.qcow2
`

	hash, err := ParseChecksums(strings.NewReader(input), "AlmaLinux-9-GenericCloud-latest.x86_64.qcow2")
	if err != nil {
		t.Fatalf("ParseChecksums failed: %v", err)
	}

	expected := "5ff9c048859046f41db4a33b1f1a96675711288078aac66b47d0be023af270d1"
	if hash != expected {
		t.Errorf("expected hash %q, got %q", expected, hash)
	}
}

func TestAlmaLinuxChecksumNotFound(t *testing.T) {
	input := `5ff9c048859046f41db4a33b1f1a96675711288078aac66b47d0be023af270d1  AlmaLinux-9-GenericCloud-latest.x86_64.qcow2
`

	_, err := ParseChecksums(strings.NewReader(input), "nonexistent.qcow2")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestAlmaLinuxProviderName(t *testing.T) {
	provider := NewAlmaLinuxProvider()
	if provider.Name() != "almalinux" {
		t.Errorf("expected name 'almalinux', got %q", provider.Name())
	}
}

func TestSupportedAlmaLinuxVersions(t *testing.T) {
	versions := supportedAlmaLinuxVersions()

	if len(versions) < 3 {
		t.Errorf("expected at least 3 versions, got %d", len(versions))
	}

	// Check that versions 8, 9, and 10 are included
	found8, found9, found10 := false, false, false
	for _, v := range versions {
		if v.version == "8" {
			found8 = true
		}
		if v.version == "9" {
			found9 = true
		}
		if v.version == "10" {
			found10 = true
		}
	}

	if !found8 {
		t.Error("expected version 8 in supported versions")
	}
	if !found9 {
		t.Error("expected version 9 in supported versions")
	}
	if !found10 {
		t.Error("expected version 10 in supported versions")
	}
}
