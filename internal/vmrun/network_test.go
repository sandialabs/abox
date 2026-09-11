package vmrun

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/sandialabs/abox/internal/errhint"
)

func regPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "vmware-vnets.json")
}

func TestAllocate_LowestFreeSkipsNAT(t *testing.T) {
	reg := regPath(t)

	// First allocation should be the lowest pool number: vmnet2.
	got, err := Allocate(reg, "a")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if got != "vmnet2" {
		t.Fatalf("first allocation = %q, want vmnet2", got)
	}

	// Subsequent distinct instances get the next lowest free numbers, and vmnet8
	// (reserved NAT) is skipped.
	want := []string{"vmnet3", "vmnet4", "vmnet5", "vmnet6", "vmnet7", "vmnet9"}
	for i, w := range want {
		inst := string(rune('b' + i))
		got, err := Allocate(reg, inst)
		if err != nil {
			t.Fatalf("Allocate %s: %v", inst, err)
		}
		if got != w {
			t.Fatalf("allocation for %s = %q, want %q (vmnet8 must be skipped)", inst, got, w)
		}
	}
}

func TestAllocate_Idempotent(t *testing.T) {
	reg := regPath(t)
	first, err := Allocate(reg, "dev")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	second, err := Allocate(reg, "dev")
	if err != nil {
		t.Fatalf("Allocate (repeat): %v", err)
	}
	if first != second {
		t.Fatalf("idempotent Allocate returned %q then %q", first, second)
	}
	// A second instance must not collide with the first.
	other, err := Allocate(reg, "other")
	if err != nil {
		t.Fatalf("Allocate other: %v", err)
	}
	if other == first {
		t.Fatalf("distinct instances got same vmnet %q", other)
	}
}

func TestRelease_FreesSlot(t *testing.T) {
	reg := regPath(t)
	a, _ := Allocate(reg, "a")
	if a != "vmnet2" {
		t.Fatalf("setup: a=%q want vmnet2", a)
	}
	if err := Release(reg, "a"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, ok := Lookup(reg, "a"); ok {
		t.Fatal("Lookup still finds released instance")
	}
	// The freed lowest slot is reused.
	b, err := Allocate(reg, "b")
	if err != nil {
		t.Fatalf("Allocate b: %v", err)
	}
	if b != "vmnet2" {
		t.Fatalf("after release, b=%q want reused vmnet2", b)
	}
}

func TestRelease_UnknownIsNoop(t *testing.T) {
	reg := regPath(t)
	if err := Release(reg, "nope"); err != nil {
		t.Fatalf("Release of unknown instance should be nil, got %v", err)
	}
}

func TestLookup(t *testing.T) {
	reg := regPath(t)
	if _, ok := Lookup(reg, "x"); ok {
		t.Fatal("Lookup found unallocated instance")
	}
	want, _ := Allocate(reg, "x")
	got, ok := Lookup(reg, "x")
	if !ok || got != want {
		t.Fatalf("Lookup = %q,%v want %q,true", got, ok, want)
	}
}

func TestAllocate_Exhaustion(t *testing.T) {
	reg := regPath(t)
	// Pool is [2..19] minus 8 = 17 slots.
	const slots = (vmnetPoolHigh - vmnetPoolLow + 1) - 1
	for i := range slots {
		if _, err := Allocate(reg, "inst"+string(rune('A'+i))); err != nil {
			t.Fatalf("Allocate #%d: %v", i, err)
		}
	}
	_, err := Allocate(reg, "overflow")
	if err == nil {
		t.Fatal("expected exhaustion error")
	}
	if !errors.Is(err, ErrVMNetExhausted) {
		t.Fatalf("error = %v, want ErrVMNetExhausted", err)
	}
	var eh *errhint.ErrHint
	if !errors.As(err, &eh) {
		t.Fatalf("exhaustion error should be an *errhint.ErrHint, got %T", err)
	}
	if eh.Hint == "" {
		t.Fatal("exhaustion errhint should carry a remediation hint")
	}
}

func TestSaveRegistry_AtomicNoTempLeft(t *testing.T) {
	reg := regPath(t)
	if _, err := Allocate(reg, "a"); err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(reg))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") || strings.HasPrefix(e.Name(), ".vmware-vnets-") {
			t.Fatalf("temp file left behind after atomic write: %s", e.Name())
		}
	}
	// Registry file itself must exist.
	if _, err := os.Stat(reg); err != nil {
		t.Fatalf("registry file missing: %v", err)
	}
}

func TestAllocate_ConcurrentNoDoubleAssign(t *testing.T) {
	reg := regPath(t)
	const n = 12
	var wg sync.WaitGroup
	results := make([]string, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = Allocate(reg, "inst"+string(rune('A'+i)))
		}(i)
	}
	wg.Wait()

	seen := map[string]bool{}
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("Allocate #%d: %v", i, errs[i])
		}
		if seen[results[i]] {
			t.Fatalf("vmnet %q double-assigned across concurrent Allocate", results[i])
		}
		seen[results[i]] = true
	}
	if len(seen) != n {
		t.Fatalf("got %d distinct vmnets, want %d", len(seen), n)
	}
}

func TestAllocatedInstances(t *testing.T) {
	reg := regPath(t)
	_, _ = Allocate(reg, "zeta")
	_, _ = Allocate(reg, "alpha")
	got := AllocatedInstances(reg)
	want := []string{"alpha", "zeta"}
	sort.Strings(got)
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("AllocatedInstances = %v, want %v", got, want)
	}
}

func TestAssertNoUplink_RejectAndAllow(t *testing.T) {
	forbidden := [][]string{
		{"nat"},
		{"NAT"},
		{"--nat"},
		{"nat=yes"},
		{"bridged"},
		{"bridge"},
		{"uplink"},
		{"connectiontype=nat"},
		{"set", "adapter", "vmnet2", "connectionType", "bridged"},
		{"--", "set", "vnet", "vmnet8", "NAT", "yes"},
	}
	for _, args := range forbidden {
		if err := assertNoUplink(args); err == nil {
			t.Errorf("assertNoUplink(%v) = nil, want error", args)
		} else if !errors.Is(err, errUplinkForbidden) {
			t.Errorf("assertNoUplink(%v) error not errUplinkForbidden: %v", args, err)
		}
	}

	allowed := [][]string{
		{"--", "add", "adapter", "vmnet2"},
		{"--", "set", "adapter", "vmnet2", "addr", "10.10.10.1"},
		{"--", "set", "adapter", "vmnet2", "mask", "255.255.255.0"},
		{"--", "update", "adapter", "vmnet2"},
		{"--", "remove", "adapter", "vmnet3"},
	}
	for _, args := range allowed {
		if err := assertNoUplink(args); err != nil {
			t.Errorf("assertNoUplink(%v) = %v, want nil", args, err)
		}
	}
}

func TestUnconfigureHostOnly_SurfacesGuardRejection(t *testing.T) {
	// The seam must never even be reached for a forbidden argument; the guard
	// rejection must propagate (not be swallowed as "best-effort not found").
	called := false
	restore := SetRunCommandForTest(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		called = true
		return nil, nil
	})
	defer restore()
	err := UnconfigureHostOnly(context.Background(), "vmnet-nat") // contains "nat"
	if err == nil {
		t.Fatal("expected guard rejection to propagate")
	}
	if !errors.Is(err, errUplinkForbidden) {
		t.Fatalf("error = %v, want errUplinkForbidden", err)
	}
	if called {
		t.Fatal("runCommand must not be called for a guard-rejected argument")
	}
}

func TestRegistry_MalformedJSON(t *testing.T) {
	reg := regPath(t)
	if err := os.WriteFile(reg, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("write malformed registry: %v", err)
	}
	// Error-surfacing variants must report the parse failure.
	if _, _, err := LookupErr(reg, "x"); err == nil {
		t.Error("LookupErr should surface parse error on malformed registry")
	}
	if _, err := AllocatedInstancesErr(reg); err == nil {
		t.Error("AllocatedInstancesErr should surface parse error on malformed registry")
	}
	// Allocate must also refuse to proceed against a corrupt registry (rather than
	// overwriting it and double-allocating).
	if _, err := Allocate(reg, "x"); err == nil {
		t.Error("Allocate should fail on malformed registry")
	}
	// Degrading variants return empty but do not panic.
	if _, ok := Lookup(reg, "x"); ok {
		t.Error("Lookup should report not-found on malformed registry")
	}
	if got := AllocatedInstances(reg); got != nil {
		t.Errorf("AllocatedInstances on malformed registry = %v, want nil", got)
	}
}
