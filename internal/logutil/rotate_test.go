package logutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotateWriter_Write(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := NewRotateWriter(path, RotateConfig{MaxSize: 1024, MaxBackups: 3})
	if err != nil {
		t.Fatalf("NewRotateWriter failed: %v", err)
	}
	defer func() { _ = w.Close() }()

	data := []byte("hello world\n")
	n, err := w.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write returned %d, want %d", n, len(data))
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(content) != "hello world\n" {
		t.Errorf("got %q, want %q", string(content), "hello world\n")
	}
}

func TestRotateWriter_Rotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	// Small MaxSize to trigger rotation
	w, err := NewRotateWriter(path, RotateConfig{MaxSize: 50, MaxBackups: 3})
	if err != nil {
		t.Fatalf("NewRotateWriter failed: %v", err)
	}
	defer func() { _ = w.Close() }()

	// Write enough data to trigger rotation
	chunk := strings.Repeat("x", 30) + "\n"
	for i := range 5 {
		if _, err := w.Write([]byte(chunk)); err != nil {
			t.Fatalf("Write %d failed: %v", i, err)
		}
	}

	// Check that backup files exist
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Error("expected backup .1 to exist")
	}
}

func TestRotateWriter_MaxBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := NewRotateWriter(path, RotateConfig{MaxSize: 20, MaxBackups: 2})
	if err != nil {
		t.Fatalf("NewRotateWriter failed: %v", err)
	}
	defer func() { _ = w.Close() }()

	// Write enough data to trigger multiple rotations
	for i := range 10 {
		if _, err := w.Write([]byte(strings.Repeat("a", 25) + "\n")); err != nil {
			t.Fatalf("Write %d failed: %v", i, err)
		}
	}

	// Backup .3 should NOT exist (maxBackups=2)
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Error("backup .3 should not exist with maxBackups=2")
	}
}

func TestRotateWriter_Close(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := NewRotateWriter(path, RotateConfig{MaxSize: 1024, MaxBackups: 3})
	if err != nil {
		t.Fatalf("NewRotateWriter failed: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Double close should be fine
	if err := w.Close(); err != nil {
		t.Fatalf("double Close failed: %v", err)
	}
}

func TestRotateWriter_DefaultConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	// Zero-value config should get defaults
	w, err := NewRotateWriter(path, RotateConfig{})
	if err != nil {
		t.Fatalf("NewRotateWriter failed: %v", err)
	}
	defer func() { _ = w.Close() }()

	if w.config.MaxSize != DefaultMaxSize {
		t.Errorf("MaxSize = %d, want %d", w.config.MaxSize, DefaultMaxSize)
	}
	if w.config.MaxBackups != DefaultMaxBackups {
		t.Errorf("MaxBackups = %d, want %d", w.config.MaxBackups, DefaultMaxBackups)
	}
}

func TestRotateWriter_Size(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := NewRotateWriter(path, RotateConfig{MaxSize: 1024, MaxBackups: 3})
	if err != nil {
		t.Fatalf("NewRotateWriter failed: %v", err)
	}
	defer func() { _ = w.Close() }()

	if _, err := w.Write([]byte("12345")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if size := w.Size(); size != 5 {
		t.Errorf("Size() = %d, want 5", size)
	}
}
