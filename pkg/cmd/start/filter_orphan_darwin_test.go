//go:build darwin

package start

import (
	"bytes"
	"errors"
	"testing"
)

func withPgrep(t *testing.T, fn func(string) ([]int, error)) {
	t.Helper()
	prev := pgrepLookup
	pgrepLookup = fn
	t.Cleanup(func() { pgrepLookup = prev })
}

// TestFindOrphanedDaemonPIDs_PatternIsInstanceSpecific verifies the discovery
// pattern anchors on "<type> serve <name>" so it matches only this instance's
// daemon, not another instance's or an unrelated process.
func TestFindOrphanedDaemonPIDs_Pattern(t *testing.T) {
	var gotPattern string
	withPgrep(t, func(pattern string) ([]int, error) {
		gotPattern = pattern
		return []int{1234}, nil
	})

	pids, err := findOrphanedDaemonPIDs("claude", "dns")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "dns serve claude"; gotPattern != want {
		t.Fatalf("pattern = %q, want %q", gotPattern, want)
	}
	if len(pids) != 1 || pids[0] != 1234 {
		t.Fatalf("pids = %v, want [1234]", pids)
	}
}

func TestFindOrphanedDaemonPIDs_HTTPType(t *testing.T) {
	var gotPattern string
	withPgrep(t, func(pattern string) ([]int, error) {
		gotPattern = pattern
		return nil, nil
	})
	if _, err := findOrphanedDaemonPIDs("my-box", "http"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "http serve my-box"; gotPattern != want {
		t.Fatalf("pattern = %q, want %q", gotPattern, want)
	}
}

// TestReclaim_SkipsUnverifiedPIDs ensures a candidate PID whose identity cannot
// be confirmed is never terminated. We assert this by confirming terminateOrphan
// is never reached for such a PID: we use the identity seam to return an error
// and rely on the fact that a non-existent test PID would be a no-op anyway, but
// to make the guarantee explicit we check the user-facing output does not claim
// a reclaim happened.
func TestReclaim_SkipsUnverifiedPIDs(t *testing.T) {
	// A high, almost-certainly-dead PID so even if logic regressed, no real
	// process is signaled. The identity seam forces "unverifiable".
	withPgrep(t, func(string) ([]int, error) { return []int{987654}, nil })
	prevID := isAboxProcessFn
	isAboxProcessFn = func(int) (bool, error) { return false, errors.New("unverifiable") }
	t.Cleanup(func() { isAboxProcessFn = prevID })

	var buf bytes.Buffer
	reclaimOrphanedFilterDaemon(&buf, "claude", "dns")

	if bytes.Contains(buf.Bytes(), []byte("reclaiming")) {
		t.Fatalf("must not report reclaiming an unverified PID; output=%q", buf.String())
	}
}

// TestReclaim_SkipsConfirmedNotAbox ensures a candidate confirmed to be some
// other program is left alone.
func TestReclaim_SkipsConfirmedNotAbox(t *testing.T) {
	withPgrep(t, func(string) ([]int, error) { return []int{987654}, nil })
	prevID := isAboxProcessFn
	isAboxProcessFn = func(int) (bool, error) { return false, nil }
	t.Cleanup(func() { isAboxProcessFn = prevID })

	var buf bytes.Buffer
	reclaimOrphanedFilterDaemon(&buf, "claude", "dns")
	if bytes.Contains(buf.Bytes(), []byte("reclaiming")) {
		t.Fatalf("must not reclaim a confirmed non-abox PID; output=%q", buf.String())
	}
}

// TestReclaim_NoCandidatesIsNoop verifies a clean run when pgrep finds nothing.
func TestReclaim_NoCandidatesIsNoop(t *testing.T) {
	withPgrep(t, func(string) ([]int, error) { return nil, nil })
	var buf bytes.Buffer
	reclaimOrphanedFilterDaemon(&buf, "claude", "dns")
	if buf.Len() != 0 {
		t.Fatalf("expected no output, got %q", buf.String())
	}
}

// TestReclaim_DiscoveryErrorIsNoop verifies a pgrep error doesn't panic or
// report a reclaim.
func TestReclaim_DiscoveryErrorIsNoop(t *testing.T) {
	withPgrep(t, func(string) ([]int, error) { return nil, errors.New("pgrep boom") })
	var buf bytes.Buffer
	reclaimOrphanedFilterDaemon(&buf, "claude", "dns")
	if buf.Len() != 0 {
		t.Fatalf("expected no output on discovery error, got %q", buf.String())
	}
}
