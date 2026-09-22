package backend_test

import (
	"errors"
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/backend/mock"
)

// defaulterBackend embeds mock.Backend and implements backend.NetworkDefaulter so
// ResolveNetwork's per-backend hook path is exercised.
type defaulterBackend struct {
	*mock.Backend
	subnet, gateway string
	err             error
}

func (d defaulterBackend) NetworkDefaults() (string, string, error) {
	return d.subnet, d.gateway, d.err
}

func TestResolveNetwork_RequestedVerbatim(t *testing.T) {
	subnet, gateway, third, err := backend.ResolveNetwork(&mock.Backend{}, "192.168.50.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subnet != "192.168.50.0/24" {
		t.Errorf("subnet = %q, want it returned verbatim", subnet)
	}
	if third != 50 {
		t.Errorf("thirdOctet = %d, want 50", third)
	}
	if gateway == "" {
		t.Error("gateway should be derived from the requested subnet")
	}
}

func TestResolveNetwork_RequestedInvalid(t *testing.T) {
	if _, _, _, err := backend.ResolveNetwork(&mock.Backend{}, "not-a-cidr"); err == nil {
		t.Fatal("expected an error for an invalid requested subnet")
	}
}

func TestResolveNetwork_NetworkDefaulterSupplies(t *testing.T) {
	// ResolveNetwork now validates the defaulter's subnet via config.ValidateSubnet,
	// which scans existing instances for conflicts — isolate the data dir so the
	// test is hermetic.
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	be := defaulterBackend{Backend: &mock.Backend{}, subnet: "192.168.130.0/24", gateway: "192.168.130.1"}
	subnet, gateway, third, err := backend.ResolveNetwork(be, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subnet != "192.168.130.0/24" || gateway != "192.168.130.1" {
		t.Errorf("got subnet=%q gateway=%q, want the defaulter's values", subnet, gateway)
	}
	if third != 130 {
		t.Errorf("thirdOctet = %d, want 130 (derived from the CIDR)", third)
	}
}

func TestResolveNetwork_NetworkDefaulterError(t *testing.T) {
	be := defaulterBackend{Backend: &mock.Backend{}, err: errPoolExhausted}
	if _, _, _, err := backend.ResolveNetwork(be, ""); !errors.Is(err, errPoolExhausted) {
		t.Fatalf("expected the defaulter error to propagate, got: %v", err)
	}
}

func TestResolveNetwork_NetworkDefaulterInvalidSubnet(t *testing.T) {
	// A defaulter that returns a malformed subnet (with a nil error) must be
	// rejected — not silently persisted into instance config — mirroring the
	// validation the requested-subnet path already performs.
	for _, bad := range []string{"", "not-a-cidr", "10.0.0.0/16", "10.0.0.5/24"} {
		be := defaulterBackend{Backend: &mock.Backend{}, subnet: bad, gateway: "10.0.0.1"}
		if _, _, _, err := backend.ResolveNetwork(be, ""); err == nil {
			t.Errorf("expected an error for invalid defaulter subnet %q, got nil", bad)
		}
	}
}

func TestResolveNetwork_FallsBackToAllocator(t *testing.T) {
	// A backend that does NOT implement NetworkDefaulter falls through to
	// config.AllocateSubnet. Isolate the data dir so allocation is hermetic.
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	subnet, gateway, _, err := backend.ResolveNetwork(&mock.Backend{}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subnet == "" || gateway == "" {
		t.Errorf("allocator should return a subnet/gateway, got subnet=%q gateway=%q", subnet, gateway)
	}
}

// errPoolExhausted is a sentinel used to assert error propagation.
var errPoolExhausted = &poolErr{}

type poolErr struct{}

func (*poolErr) Error() string { return "pool exhausted" }
