package config

import (
	"strings"
	"testing"
)

func TestLoad_CorruptedYAML(t *testing.T) {
	mock := NewMockFileSystem()
	mock.HomeDir = "/home/testuser"

	// Set up directory structure so GetPaths works
	configPath := "/home/testuser/.local/share/abox/instances/corrupt/config.yaml"
	mock.Files[configPath] = []byte("{{invalid yaml: [unterminated")
	mock.Dirs["/home/testuser/.local/share/abox/instances/corrupt"] = true

	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	_, _, err := Load("corrupt")
	if err == nil {
		t.Fatal("expected error for corrupted YAML")
	}
	if !strings.Contains(err.Error(), "failed to parse config") {
		t.Errorf("error should mention parse failure, got: %v", err)
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	mock := NewMockFileSystem()
	mock.HomeDir = "/home/testuser"

	configPath := "/home/testuser/.local/share/abox/instances/empty/config.yaml"
	mock.Files[configPath] = []byte("")
	mock.Dirs["/home/testuser/.local/share/abox/instances/empty"] = true

	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	// Empty YAML should unmarshal to zero-value struct, which will fail version check
	_, _, err := Load("empty")
	if err == nil {
		t.Fatal("expected error for empty config file")
	}
}

func TestLoad_InvalidYAMLTypes(t *testing.T) {
	mock := NewMockFileSystem()
	mock.HomeDir = "/home/testuser"

	// YAML where a scalar field is given a map value (type mismatch)
	configPath := "/home/testuser/.local/share/abox/instances/badtype/config.yaml"
	mock.Files[configPath] = []byte("version: 1\nname:\n  nested: should_be_string\n")
	mock.Dirs["/home/testuser/.local/share/abox/instances/badtype"] = true

	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	_, _, err := Load("badtype")
	if err == nil {
		t.Fatal("expected error for YAML type mismatch")
	}
}

func TestLoad_NonExistentInstance(t *testing.T) {
	mock := NewMockFileSystem()
	mock.HomeDir = "/home/testuser"

	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	_, _, err := Load("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent instance")
	}
}
