package instance

import (
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/backend/mock"
	"github.com/sandialabs/abox/internal/config"
)

// conflictOnceBackend returns a mock backend whose network Create fails with
// ErrSubnetConflict on the first call (recording each attempt's subnet) and
// succeeds afterwards.
func conflictOnceBackend(createSubnets *[]string) *mock.Backend {
	return &mock.Backend{
		NetworkFunc: func() backend.NetworkManager {
			return &mock.NetworkManager{
				CreateFunc: func(_ context.Context, in *config.Instance) error {
					*createSubnets = append(*createSubnets, in.Subnet)
					if len(*createSubnets) == 1 {
						return fmt.Errorf("subnet %s: %w", in.Subnet, backend.ErrSubnetConflict)
					}
					return nil
				},
			}
		},
	}
}

// TestCreateNetworkWithRetry_ReallocatesOnConflict: when network create reports
// backend.ErrSubnetConflict (another user double-booked the /24 between probe
// and define), the helper re-allocates a fresh subnet, persists it, and retries.
func TestCreateNetworkWithRetry_ReallocatesOnConflict(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("TMPDIR", t.TempDir())

	paths, err := config.GetPaths("dev")
	if err != nil {
		t.Fatalf("GetPaths: %v", err)
	}
	if err := config.EnsureDirs(paths); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	inst := &config.Instance{
		Version:   config.CurrentInstanceVersion,
		Name:      "dev",
		Base:      "ubuntu-24.04",
		CPUs:      2,
		Memory:    2048,
		Disk:      "20G",
		Subnet:    "10.10.10.0/24",
		Gateway:   "10.10.10.1",
		IPAddress: "10.10.10.10",
		Bridge:    "abox-dev",
	}
	// Save the config: the re-allocation scan sees this instance claiming
	// 10.10.10.0/24, making the retry deterministically pick 10.10.11.0/24.
	if err := config.Save(inst, paths); err != nil {
		t.Fatalf("Save: %v", err)
	}

	var createSubnets []string
	be := conflictOnceBackend(&createSubnets)

	if err := CreateNetworkWithRetry(context.Background(), io.Discard, be, inst, paths); err != nil {
		t.Fatalf("CreateNetworkWithRetry: %v", err)
	}
	if len(createSubnets) != 2 || createSubnets[0] != "10.10.10.0/24" || createSubnets[1] != "10.10.11.0/24" {
		t.Fatalf("create attempts = %v, want [10.10.10.0/24 10.10.11.0/24]", createSubnets)
	}
	// The re-allocated subnet (and derived addresses) must be persisted.
	reloaded, _, err := config.Load("dev")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if reloaded.Subnet != "10.10.11.0/24" || reloaded.Gateway != "10.10.11.1" {
		t.Errorf("persisted subnet/gateway = %s/%s, want 10.10.11.0/24 / 10.10.11.1", reloaded.Subnet, reloaded.Gateway)
	}
	if reloaded.IPAddress != config.DeriveHostIP("10.10.11.1") {
		t.Errorf("persisted IP = %s, want %s", reloaded.IPAddress, config.DeriveHostIP("10.10.11.1"))
	}
}

// TestCreateNetworkWithRetry_PinnedSubnetNotReallocated: a user-chosen subnet
// (SubnetPinned, recorded at create for --subnet/abox.yaml) must never be
// silently replaced — external firewall rules or docs may be keyed on it; the
// conflict surfaces as an error with guidance.
func TestCreateNetworkWithRetry_PinnedSubnetNotReallocated(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("TMPDIR", t.TempDir())
	paths, err := config.GetPaths("dev")
	if err != nil {
		t.Fatalf("GetPaths: %v", err)
	}
	inst := &config.Instance{Name: "dev", Subnet: "10.10.50.0/24", Gateway: "10.10.50.1", SubnetPinned: true}

	calls := 0
	be := &mock.Backend{
		NetworkFunc: func() backend.NetworkManager {
			return &mock.NetworkManager{
				CreateFunc: func(_ context.Context, _ *config.Instance) error {
					calls++
					return fmt.Errorf("subnet: %w", backend.ErrSubnetConflict)
				},
			}
		},
	}

	err = CreateNetworkWithRetry(context.Background(), io.Discard, be, inst, paths)
	if err == nil {
		t.Fatal("expected an error for a pinned-subnet conflict")
	}
	if calls != 1 {
		t.Errorf("create attempts = %d, want 1 (no retry for a pinned subnet)", calls)
	}
	if inst.Subnet != "10.10.50.0/24" {
		t.Errorf("pinned subnet was replaced: %s", inst.Subnet)
	}
}
