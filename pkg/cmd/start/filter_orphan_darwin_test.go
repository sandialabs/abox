//go:build darwin

package start

import (
	"errors"
	"io"
	"testing"
)

// TestFindOrphanedDaemonPattern verifies the pgrep pattern anchors the instance
// name to the end of the argv so a sibling whose name has this one as a prefix
// (e.g. "dev" vs "dev2") is not matched.
func TestFindOrphanedDaemonPattern(t *testing.T) {
	var gotPattern string
	orig := pgrepLookup
	pgrepLookup = func(pattern string) ([]int, error) {
		gotPattern = pattern
		return nil, nil
	}
	defer func() { pgrepLookup = orig }()

	if _, err := findOrphanedDaemonPIDs("dev", "dns"); err != nil {
		t.Fatalf("findOrphanedDaemonPIDs: %v", err)
	}
	if want := "dns serve dev$"; gotPattern != want {
		t.Errorf("pattern = %q, want %q", gotPattern, want)
	}
}

// TestReclaimSkipsUnverifiablePIDs ensures a candidate PID that cannot be
// positively confirmed as an abox process is left alone (never terminated), and
// that a confirmed-abox PID IS terminated exactly once. It asserts via the
// terminateOrphanFn seam rather than relying on "did not panic".
func TestReclaimSkipsUnverifiablePIDs(t *testing.T) {
	origLookup := pgrepLookup
	origID := isAboxProcessFn
	origTerm := terminateOrphanFn
	defer func() {
		pgrepLookup = origLookup
		isAboxProcessFn = origID
		terminateOrphanFn = origTerm
	}()

	pgrepLookup = func(string) ([]int, error) { return []int{999999}, nil }
	var terminated []int
	terminateOrphanFn = func(pid int) { terminated = append(terminated, pid) }

	// Case 1: unverifiable (error) -> must NOT be terminated.
	isAboxProcessFn = func(int) (bool, error) { return false, errors.New("cannot verify") }
	reclaimOrphanedFilterDaemon(io.Discard, "dev", "dns")
	if len(terminated) != 0 {
		t.Errorf("unverifiable PID was terminated: %v", terminated)
	}

	// Case 2: confirmed NOT abox -> must NOT be terminated.
	isAboxProcessFn = func(int) (bool, error) { return false, nil }
	reclaimOrphanedFilterDaemon(io.Discard, "dev", "dns")
	if len(terminated) != 0 {
		t.Errorf("confirmed-not-abox PID was terminated: %v", terminated)
	}

	// Case 3: confirmed abox -> terminated exactly once with the right PID.
	isAboxProcessFn = func(int) (bool, error) { return true, nil }
	reclaimOrphanedFilterDaemon(io.Discard, "dev", "dns")
	if len(terminated) != 1 || terminated[0] != 999999 {
		t.Errorf("confirmed-abox PID should be terminated once, got: %v", terminated)
	}
}
