package factory

import (
	"errors"
	"io"
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
)

// fakeBackend is a minimal backend.Backend used to exercise factory selection,
// caching, and egress-provider injection without touching real hypervisors.
type fakeBackend struct {
	name                    string
	available               error
	injectedProvider        backend.EgressEnforcerProvider
	providerSet             bool
	injectedStorageProvider backend.StorageEnforcerProvider
	storageProviderSet      bool
	injectedPfProvider      backend.PfEnforcerProvider
	pfProviderSet           bool
}

func (f *fakeBackend) Name() string                               { return f.name }
func (f *fakeBackend) IsAvailable() error                         { return f.available }
func (f *fakeBackend) VM() backend.VMManager                      { return nil }
func (f *fakeBackend) Network() backend.NetworkManager            { return nil }
func (f *fakeBackend) Disk() backend.DiskManager                  { return nil }
func (f *fakeBackend) Snapshot() backend.SnapshotManager          { return nil }
func (f *fakeBackend) EgressController() backend.EgressController { return nil }
func (f *fakeBackend) MonitorTransport() backend.MonitorTransport { return nil }
func (f *fakeBackend) DryRun(_ *config.Instance, _ *config.Paths, _ io.Writer, _ backend.VMCreateOptions) error {
	return nil
}
func (f *fakeBackend) ResourceNames(instanceName string) backend.ResourceNames {
	return backend.ResourceNames{Instance: instanceName}
}
func (f *fakeBackend) GenerateMAC() string { return "00:00:00:00:00:00" }
func (f *fakeBackend) StorageDir() string  { return "/tmp/fake-backend" }

// SetEgressProvider records the injected provider so tests can assert the factory
// wired it (implements backend.EgressProviderSetter).
func (f *fakeBackend) SetEgressProvider(p backend.EgressEnforcerProvider) {
	f.providerSet = true
	f.injectedProvider = p
}

// SetStorageProvider records the injected storage provider so tests can assert
// the factory wired it (implements backend.StorageProviderSetter).
func (f *fakeBackend) SetStorageProvider(p backend.StorageEnforcerProvider) {
	f.storageProviderSet = true
	f.injectedStorageProvider = p
}

// SetPfProvider records the injected pf provider so tests can assert the factory
// wired it (implements backend.PfProviderSetter).
func (f *fakeBackend) SetPfProvider(p backend.PfEnforcerProvider) {
	f.pfProviderSet = true
	f.injectedPfProvider = p
}

var (
	_ backend.EgressProviderSetter  = (*fakeBackend)(nil)
	_ backend.StorageProviderSetter = (*fakeBackend)(nil)
	_ backend.PfProviderSetter      = (*fakeBackend)(nil)
)

// registerFake installs a fake backend factory under name and returns a pointer
// to a counter incremented on every factory invocation (i.e., every resolve/Get
// that constructs the backend). The registry is reset in t.Cleanup.
func registerFake(t *testing.T, available error) *int {
	t.Helper()
	backend.ResetForTesting()
	t.Cleanup(backend.ResetForTesting)

	const (
		name     = "fake"
		priority = 10
	)
	count := 0
	backend.Register(name, priority, func() backend.Backend {
		count++
		return &fakeBackend{name: name, available: available}
	})
	return &count
}

func TestResolveBackendHonorsEnv(t *testing.T) {
	registerFake(t, nil)
	t.Setenv(EnvBackend, "fake")

	b, err := resolveBackend()
	if err != nil {
		t.Fatalf("resolveBackend: %v", err)
	}
	if b.Name() != "fake" {
		t.Errorf("resolveBackend Name = %q, want fake", b.Name())
	}
}

func TestResolveBackendEnvUnregistered(t *testing.T) {
	registerFake(t, nil)
	t.Setenv(EnvBackend, "nope")

	if _, err := resolveBackend(); err == nil {
		t.Fatal("resolveBackend must error when ABOX_BACKEND names an unregistered backend")
	}
}

func TestResolveBackendFallsBackToAutoDetect(t *testing.T) {
	registerFake(t, nil)
	t.Setenv(EnvBackend, "") // unset -> auto-detect

	b, err := resolveBackend()
	if err != nil {
		t.Fatalf("resolveBackend: %v", err)
	}
	if b.Name() != "fake" {
		t.Errorf("resolveBackend auto-detect Name = %q, want fake", b.Name())
	}
}

func TestBackendForUsesConfigBackendAndCaches(t *testing.T) {
	count := registerFake(t, nil)

	f := New()
	// Stub Config so the instance reports the "fake" backend.
	f.Config = func(name string) (*config.Instance, *config.Paths, error) {
		return &config.Instance{Name: name, Backend: "fake"}, &config.Paths{}, nil
	}

	b1, err := f.BackendFor("inst")
	if err != nil {
		t.Fatalf("BackendFor: %v", err)
	}
	if b1.Name() != "fake" {
		t.Errorf("BackendFor Name = %q, want fake", b1.Name())
	}
	afterFirst := *count
	if afterFirst == 0 {
		t.Fatal("factory closure was never invoked on the first BackendFor; the cache assertion below would be vacuous")
	}

	// Second call for the same instance must hit the cache and NOT re-resolve
	// (the factory closure must not be invoked again).
	b2, err := f.BackendFor("inst")
	if err != nil {
		t.Fatalf("BackendFor (cached): %v", err)
	}
	if b1 != b2 {
		t.Error("BackendFor must return the cached backend instance on the second call")
	}
	if *count != afterFirst {
		t.Errorf("BackendFor re-resolved on cache hit: factory invoked %d times, want %d", *count, afterFirst)
	}
}

func TestBackendForReportsUnavailableConfigBackend(t *testing.T) {
	registerFake(t, errors.New("not here"))

	f := New()
	f.Config = func(name string) (*config.Instance, *config.Paths, error) {
		return &config.Instance{Name: name, Backend: "fake"}, &config.Paths{}, nil
	}

	if _, err := f.BackendFor("inst"); err == nil {
		t.Fatal("BackendFor must error when the config's backend is unavailable")
	}
}

func TestBackendForResolvesWhenConfigMissing(t *testing.T) {
	registerFake(t, nil)
	t.Setenv(EnvBackend, "fake")

	f := New()
	// Config load fails (instance does not exist) -> fall back to resolveBackend.
	f.Config = func(name string) (*config.Instance, *config.Paths, error) {
		return nil, nil, errors.New("no such instance")
	}

	b, err := f.BackendFor("newinst")
	if err != nil {
		t.Fatalf("BackendFor: %v", err)
	}
	if b.Name() != "fake" {
		t.Errorf("BackendFor Name = %q, want fake", b.Name())
	}
}

func TestInjectEgressProviderWiresProvider(t *testing.T) {
	registerFake(t, nil)

	f := New()
	fb := &fakeBackend{name: "fake"}
	f.injectEgressProvider(fb, "inst")

	if !fb.providerSet {
		t.Fatal("injectEgressProvider must call SetEgressProvider on a backend implementing EgressProviderSetter")
	}
	if fb.injectedProvider == nil {
		t.Fatal("injectEgressProvider must wire a non-nil provider closure")
	}
}

func TestInjectEgressProviderIgnoresNonSetter(t *testing.T) {
	// A backend that does NOT implement EgressProviderSetter must be tolerated
	// (injectEgressProvider early-returns). This must not panic.
	registerFake(t, nil)
	f := New()
	f.injectEgressProvider(&nonSetterBackend{}, "inst")
}

func TestInjectStorageProviderWiresProvider(t *testing.T) {
	registerFake(t, nil)

	f := New()
	fb := &fakeBackend{name: "fake"}
	f.injectStorageProvider(fb, "inst")

	if !fb.storageProviderSet {
		t.Fatal("injectStorageProvider must call SetStorageProvider on a backend implementing StorageProviderSetter")
	}
	if fb.injectedStorageProvider == nil {
		t.Fatal("injectStorageProvider must wire a non-nil provider closure")
	}
}

func TestInjectPfProviderWiresProvider(t *testing.T) {
	registerFake(t, nil)

	f := New()
	fb := &fakeBackend{name: "fake"}
	f.injectPfProvider(fb, "inst")

	if !fb.pfProviderSet {
		t.Fatal("injectPfProvider must call SetPfProvider on a backend implementing PfProviderSetter")
	}
	if fb.injectedPfProvider == nil {
		t.Fatal("injectPfProvider must wire a non-nil provider closure")
	}
}

func TestInjectPfProviderIgnoresNonSetter(t *testing.T) {
	// A backend that does NOT implement PfProviderSetter must be tolerated
	// (injectPfProvider early-returns). This must not panic.
	registerFake(t, nil)
	f := New()
	f.injectPfProvider(&nonSetterBackend{}, "inst")
}

func TestInjectStorageProviderIgnoresNonSetter(t *testing.T) {
	// A backend that does NOT implement StorageProviderSetter must be tolerated
	// (injectStorageProvider early-returns). nonSetterBackend implements neither
	// the egress nor the storage setter. This must not panic.
	registerFake(t, nil)
	f := New()
	f.injectStorageProvider(&nonSetterBackend{}, "inst")
}

// nonSetterBackend implements backend.Backend but NOT EgressProviderSetter, to
// exercise the injectEgressProvider early-return path.
type nonSetterBackend struct{}

func (nonSetterBackend) Name() string                               { return "nonsetter" }
func (nonSetterBackend) IsAvailable() error                         { return nil }
func (nonSetterBackend) VM() backend.VMManager                      { return nil }
func (nonSetterBackend) Network() backend.NetworkManager            { return nil }
func (nonSetterBackend) Disk() backend.DiskManager                  { return nil }
func (nonSetterBackend) Snapshot() backend.SnapshotManager          { return nil }
func (nonSetterBackend) EgressController() backend.EgressController { return nil }
func (nonSetterBackend) MonitorTransport() backend.MonitorTransport { return nil }
func (nonSetterBackend) DryRun(_ *config.Instance, _ *config.Paths, _ io.Writer, _ backend.VMCreateOptions) error {
	return nil
}
func (nonSetterBackend) ResourceNames(instanceName string) backend.ResourceNames {
	return backend.ResourceNames{Instance: instanceName}
}
func (nonSetterBackend) GenerateMAC() string { return "00:00:00:00:00:00" }
func (nonSetterBackend) StorageDir() string  { return "/tmp/nonsetter" }
