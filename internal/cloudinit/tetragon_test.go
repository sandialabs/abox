package cloudinit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sandialabs/abox/internal/tetragon"
)

func TestCheckTetragonCached_NotExists(t *testing.T) {
	// Non-existent file should return false
	result := checkTetragonCached("/nonexistent/path/tetragon.tar.gz", "somehash")
	if result {
		t.Error("checkTetragonCached should return false for non-existent file")
	}
}

func TestCheckTetragonCached_WrongChecksum(t *testing.T) {
	// Create a file with wrong content
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "tetragon.tar.gz")
	if err := os.WriteFile(tmpFile, []byte("wrong content"), 0o644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	result := checkTetragonCached(tmpFile, "expectedhash")
	if result {
		t.Error("checkTetragonCached should return false for file with wrong checksum")
	}
}

func TestCheckTetragonCached_CorrectChecksum(t *testing.T) {
	// Create a file with known content
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "tetragon.tar.gz")
	content := []byte("test content")
	if err := os.WriteFile(tmpFile, content, 0o644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	// SHA256 of "test content"
	expectedHash := "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72"

	result := checkTetragonCached(tmpFile, expectedHash)
	if !result {
		t.Error("checkTetragonCached should return true for file with correct checksum")
	}
}

func TestTarballFilename(t *testing.T) {
	tests := []struct {
		version  string
		expected string
	}{
		{"v1.3.0", "tetragon-v1.3.0-amd64.tar.gz"},
		{"v1.6.0", "tetragon-v1.6.0-amd64.tar.gz"},
	}

	for _, tt := range tests {
		got := tetragon.TarballFilename(tt.version)
		if got != tt.expected {
			t.Errorf("TarballFilename(%q) = %q, want %q", tt.version, got, tt.expected)
		}
	}
}
