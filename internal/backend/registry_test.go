package backend

import (
	"errors"
	"io"
	"testing"

	"github.com/sandialabs/abox/internal/config"
)

var errNotSupported = errors.New("not supported")

// mockBackend is a test implementation of Backend
type mockBackend struct {
	name      string
	available error
}

func (m *mockBackend) Name() string                           { return m.name }
func (m *mockBackend) IsAvailable() error                     { return m.available }
func (m *mockBackend) VM() VMManager                          { return nil }
func (m *mockBackend) Network() NetworkManager                { return nil }
func (m *mockBackend) Disk() DiskManager                      { return nil }
func (m *mockBackend) Snapshot() SnapshotManager              { return nil }
func (m *mockBackend) TrafficInterceptor() TrafficInterceptor { return nil }
func (m *mockBackend) DryRun(_ *config.Instance, _ *config.Paths, _ io.Writer, _ VMCreateOptions) error {
	return nil
}
func (m *mockBackend) ResourceNames(instanceName string) ResourceNames {
	return ResourceNames{
		Instance: instanceName,
		VM:       "mock-" + instanceName,
		Network:  "mock-" + instanceName,
		Filter:   "mock-" + instanceName + "-filter",
	}
}
func (m *mockBackend) GenerateMAC() string { return "00:00:00:00:00:00" }
func (m *mockBackend) StorageDir() string  { return "/tmp/mock-backend" }

func TestRegisterAndGet(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	Register("test1", 10, func() Backend { return &mockBackend{name: "test1"} })
	Register("test2", 20, func() Backend { return &mockBackend{name: "test2"} })

	// Verify both backends can be retrieved
	b1, err := Get("test1")
	if err != nil {
		t.Errorf("Get(\"test1\") failed: %v", err)
	}
	if b1 == nil {
		t.Error("expected non-nil backend for test1")
	}

	b2, err := Get("test2")
	if err != nil {
		t.Errorf("Get(\"test2\") failed: %v", err)
	}
	if b2 == nil {
		t.Error("expected non-nil backend for test2")
	}
}

func TestAutoDetect(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	// Register available backend with lower priority
	Register("available", 10, func() Backend {
		return &mockBackend{name: "available", available: nil}
	})

	// Register unavailable backend with higher priority (lower number)
	Register("unavailable", 5, func() Backend {
		return &mockBackend{name: "unavailable", available: errNotSupported}
	})

	b, err := AutoDetect()
	if err != nil {
		t.Fatalf("AutoDetect failed: %v", err)
	}
	if b.Name() != "available" {
		t.Errorf("expected 'available' backend, got %q", b.Name())
	}
}

func TestAutoDetect_NoBackends(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	_, err := AutoDetect()
	if !errors.Is(err, ErrNoBackendAvailable) {
		t.Errorf("expected ErrNoBackendAvailable, got %v", err)
	}
}

func TestGet(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	Register("mybackend", 10, func() Backend {
		return &mockBackend{name: "mybackend", available: nil}
	})

	b, err := Get("mybackend")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if b.Name() != "mybackend" {
		t.Errorf("expected 'mybackend', got %q", b.Name())
	}
}

func TestGet_NotFound(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	_, err := Get("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent backend")
	}
}

func TestGetAvailableVsUnavailable(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	Register("available", 10, func() Backend {
		return &mockBackend{name: "available", available: nil}
	})
	Register("unavailable", 20, func() Backend {
		return &mockBackend{name: "unavailable", available: errNotSupported}
	})

	// Available backend should be retrievable
	_, err := Get("available")
	if err != nil {
		t.Errorf("Get(\"available\") should succeed, got: %v", err)
	}

	// Unavailable backend should return an error
	_, err = Get("unavailable")
	if err == nil {
		t.Error("Get(\"unavailable\") should return an error")
	}
}

// mockInstance implements the interface needed by ForInstance
type mockInstance struct {
	backend string
}

func (m *mockInstance) GetBackend() string { return m.backend }

func TestForInstance_WithBackend(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	Register("mybackend", 10, func() Backend {
		return &mockBackend{name: "mybackend", available: nil}
	})

	b, err := ForInstance(&mockInstance{backend: "mybackend"})
	if err != nil {
		t.Fatalf("ForInstance failed: %v", err)
	}
	if b.Name() != "mybackend" {
		t.Errorf("expected 'mybackend', got %q", b.Name())
	}
}

func TestForInstance_AutoDetect(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	Register("autodetected", 10, func() Backend {
		return &mockBackend{name: "autodetected", available: nil}
	})

	b, err := ForInstance(&mockInstance{backend: ""})
	if err != nil {
		t.Fatalf("ForInstance failed: %v", err)
	}
	if b.Name() != "autodetected" {
		t.Errorf("expected 'autodetected', got %q", b.Name())
	}
}
