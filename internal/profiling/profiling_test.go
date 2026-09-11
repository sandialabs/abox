package profiling

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStartNoopWhenUnset(t *testing.T) {
	t.Setenv("ABOX_CPUPROFILE", "")
	t.Setenv("ABOX_TRACE", "")

	stop := Start()
	if stop == nil {
		t.Fatal("Start returned nil stop function")
	}
	// Must not panic and must not create any files.
	stop()
}

func TestStartCPUProfileWritesFile(t *testing.T) {
	dir := t.TempDir()
	profPath := filepath.Join(dir, "cpu.prof")
	t.Setenv("ABOX_CPUPROFILE", profPath)
	t.Setenv("ABOX_TRACE", "")

	stop := Start()
	// Do a little work so the profile has something to flush.
	sum := 0
	for i := range 1_000_000 {
		sum += i
	}
	_ = sum
	stop()

	info, err := os.Stat(profPath)
	if err != nil {
		t.Fatalf("expected CPU profile at %s: %v", profPath, err)
	}
	if info.Size() == 0 {
		t.Errorf("CPU profile is empty")
	}
}

func TestStartTraceWritesFile(t *testing.T) {
	dir := t.TempDir()
	tracePath := filepath.Join(dir, "trace.out")
	t.Setenv("ABOX_CPUPROFILE", "")
	t.Setenv("ABOX_TRACE", tracePath)

	stop := Start()
	stop()

	info, err := os.Stat(tracePath)
	if err != nil {
		t.Fatalf("expected trace at %s: %v", tracePath, err)
	}
	if info.Size() == 0 {
		t.Errorf("trace file is empty")
	}
}

func TestTrackDisabledIsNoop(t *testing.T) {
	t.Setenv("ABOX_TIMINGS", "")
	// Should return a callable no-op and not panic.
	done := Track("unit:test")
	if done == nil {
		t.Fatal("Track returned nil")
	}
	done()
}

func TestTrackEnabled(t *testing.T) {
	t.Setenv("ABOX_TIMINGS", "1")
	// We can't easily capture the package's os.Stderr write here; just assert it
	// runs without panicking and returns a usable stopwatch.
	done := Track("unit:test")
	if done == nil {
		t.Fatal("Track returned nil")
	}
	done()
}
