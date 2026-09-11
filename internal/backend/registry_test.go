package backend

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/config"
)

var errNotSupported = errors.New("not supported")

// mockBackend is a test implementation of Backend
type mockBackend struct {
	name      string
	available error
}

func (m *mockBackend) Name() string                       { return m.name }
func (m *mockBackend) IsAvailable() error                 { return m.available }
func (m *mockBackend) VM() VMManager                      { return nil }
func (m *mockBackend) Network() NetworkManager            { return nil }
func (m *mockBackend) Disk() DiskManager                  { return nil }
func (m *mockBackend) Snapshot() SnapshotManager          { return nil }
func (m *mockBackend) EgressController() EgressController { return nil }
func (m *mockBackend) MonitorTransport() MonitorTransport { return nil }
func (m *mockBackend) DryRun(_ *config.Instance, _ *config.Paths, _ io.Writer, _ VMCreateOptions) error {
	return nil
}
func (m *mockBackend) ResourceNames(instanceName string) ResourceNames {
	return ResourceNames{
		Instance: instanceName,
		VM:       "mock-" + instanceName,
		Network:  "mock-" + instanceName,
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

func TestAutoDetectSkipsExperimental(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	// An available experimental backend at the best priority must NOT be chosen by
	// auto-detection; the stable one is picked instead.
	RegisterExperimental("exp", 1, func() Backend {
		return &mockBackend{name: "exp", available: nil}
	})
	Register("stable", 10, func() Backend {
		return &mockBackend{name: "stable", available: nil}
	})

	b, err := AutoDetect()
	if err != nil {
		t.Fatalf("AutoDetect: %v", err)
	}
	if b.Name() != "stable" {
		t.Errorf("AutoDetect chose %q, want stable (experimental must be skipped)", b.Name())
	}
	if !IsExperimental("exp") || IsExperimental("stable") {
		t.Error("IsExperimental should be true only for the experimental backend")
	}
}

func TestAutoDetectExperimentalOnlyErrorsWithHint(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	// Only an experimental backend is available: auto-detect must fail rather than
	// silently select it, and the error should name it for explicit selection.
	RegisterExperimental("exp", 1, func() Backend {
		return &mockBackend{name: "exp", available: nil}
	})

	_, err := AutoDetect()
	if !errors.Is(err, ErrNoBackendAvailable) {
		t.Fatalf("expected ErrNoBackendAvailable, got %v", err)
	}
	if !contains(err.Error(), "exp") || !contains(err.Error(), "ABOX_BACKEND") {
		t.Errorf("error should name the experimental backend and ABOX_BACKEND, got: %v", err)
	}

	// Explicit selection still works.
	b, err := Get("exp")
	if err != nil {
		t.Fatalf("explicit Get(exp): %v", err)
	}
	if b.Name() != "exp" {
		t.Errorf("Get(exp) = %q, want exp", b.Name())
	}
}

func TestAutoDetectExperimentalOnlyUnavailableSurfacesReason(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	// The only registered backend is experimental AND unavailable (e.g. vmware on
	// Windows without VMware installed). AutoDetect must surface the concrete
	// availability reason, not a bare ErrNoBackendAvailable with no diagnostics.
	RegisterExperimental("exp", 1, func() Backend {
		return &mockBackend{name: "exp", available: errNotSupported}
	})

	_, err := AutoDetect()
	if !errors.Is(err, ErrNoBackendAvailable) {
		t.Fatalf("expected ErrNoBackendAvailable, got %v", err)
	}
	if !contains(err.Error(), "exp") || !contains(err.Error(), errNotSupported.Error()) {
		t.Errorf("error should name the experimental backend and its reason, got: %v", err)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func TestAutoDetectSurfacesBothStableAndExperimentalReasons(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	// A host where BOTH a stable and an experimental backend errored. The error
	// must surface both reasons so the experimental diagnostics are not dropped.
	errStable := errors.New("stable is broken")
	errExp := errors.New("experimental is broken")
	Register("stable", 10, func() Backend {
		return &mockBackend{name: "stable", available: errStable}
	})
	RegisterExperimental("exp", 1, func() Backend {
		return &mockBackend{name: "exp", available: errExp}
	})

	_, err := AutoDetect()
	if !errors.Is(err, ErrNoBackendAvailable) {
		t.Fatalf("expected ErrNoBackendAvailable, got %v", err)
	}
	if !contains(err.Error(), errStable.Error()) {
		t.Errorf("error should surface the stable backend reason, got: %v", err)
	}
	if !contains(err.Error(), "exp") || !contains(err.Error(), errExp.Error()) {
		t.Errorf("error should also surface the experimental backend reason, got: %v", err)
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

// mockToolBackend is a mockBackend that also declares required tools.
type mockToolBackend struct {
	mockBackend
	tools []Tool
}

func (m *mockToolBackend) RequiredTools() []Tool { return m.tools }

func TestRequiredToolsByBackend(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	Register("withtools", 10, func() Backend {
		return &mockToolBackend{
			mockBackend: mockBackend{name: "withtools"},
			tools:       []Tool{{Name: "footool", UsedBy: "stuff", Hint: "install foo"}},
		}
	})
	Register("notools", 20, func() Backend {
		return &mockBackend{name: "notools"}
	})

	byBackend := RequiredToolsByBackend()
	if _, ok := byBackend["notools"]; ok {
		t.Error("backend without ToolRequirer should be omitted")
	}
	tools, ok := byBackend["withtools"]
	if !ok {
		t.Fatal("expected 'withtools' backend to appear")
	}
	if len(tools) != 1 || tools[0].Name != "footool" {
		t.Errorf("RequiredTools() = %v, want [footool]", tools)
	}
}

func TestIsRegistered(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	Register("present", 10, func() Backend { return &mockBackend{name: "present"} })

	if !IsRegistered("present") {
		t.Error("IsRegistered(present) = false, want true")
	}
	if IsRegistered("absent") {
		t.Error("IsRegistered(absent) = true, want false")
	}
}

func TestDefaultName(t *testing.T) {
	t.Run("none registered", func(t *testing.T) {
		ResetForTesting()
		defer ResetForTesting()
		if got := DefaultName(); got != "" {
			t.Errorf("DefaultName() = %q, want empty", got)
		}
	})

	t.Run("prefers lowest-priority non-experimental", func(t *testing.T) {
		ResetForTesting()
		defer ResetForTesting()
		RegisterExperimental("exp", 1, func() Backend { return &mockBackend{name: "exp"} })
		Register("stable", 10, func() Backend { return &mockBackend{name: "stable"} })
		Register("stable2", 20, func() Backend { return &mockBackend{name: "stable2"} })
		if got := DefaultName(); got != "stable" {
			t.Errorf("DefaultName() = %q, want stable (non-experimental, lowest priority)", got)
		}
	})

	t.Run("falls back to experimental when it is the only one", func(t *testing.T) {
		ResetForTesting()
		defer ResetForTesting()
		RegisterExperimental("exp", 1, func() Backend { return &mockBackend{name: "exp"} })
		if got := DefaultName(); got != "exp" {
			t.Errorf("DefaultName() = %q, want exp", got)
		}
	})
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
