// Package profiling provides opt-in, env-gated performance instrumentation:
// a whole-process CPU profile / execution trace (ABOX_CPUPROFILE / ABOX_TRACE)
// and lightweight per-operation wall-clock timings (ABOX_TIMINGS). Every hook is
// a no-op unless its environment variable is set, so a normal run pays no cost
// and produces no extra output.
//
// The two knobs are complementary: CPU profiling only sees in-process work
// (gzip, tar, io.Copy), while several hot paths shell out to subprocesses such
// as qemu-img — for those, only the wall-clock Track timings attribute the cost.
package profiling

import (
	"fmt"
	"os"
	"runtime/pprof"
	"runtime/trace"
	"slices"
	"time"

	"github.com/sandialabs/abox/internal/logging"
)

// Start begins any profiling requested via environment variables and returns a
// stop function that flushes and closes the active profiles. It is safe to call
// unconditionally; when no profiling env vars are set it returns a no-op stop.
// Wire it once near process entry:
//
//	stop := profiling.Start()
//	defer stop()
func Start() func() {
	var stoppers []func()

	if path := os.Getenv("ABOX_CPUPROFILE"); path != "" {
		// Profile path is deliberately operator-specified (a local developer
		// profiling knob writing to a path the operator already controls).
		if f, err := os.Create(path); err != nil { //nolint:gosec // G703: operator-chosen profile path
			logging.Warn("could not create CPU profile", "path", path, "error", err)
		} else if err := pprof.StartCPUProfile(f); err != nil {
			logging.Warn("could not start CPU profile", "error", err)
			_ = f.Close()
		} else {
			stoppers = append(stoppers, func() {
				pprof.StopCPUProfile()
				_ = f.Close()
			})
		}
	}

	if path := os.Getenv("ABOX_TRACE"); path != "" {
		// Operator-specified trace path (see ABOX_CPUPROFILE above).
		if f, err := os.Create(path); err != nil { //nolint:gosec // G703: operator-chosen trace path
			logging.Warn("could not create trace file", "path", path, "error", err)
		} else if err := trace.Start(f); err != nil {
			logging.Warn("could not start execution trace", "error", err)
			_ = f.Close()
		} else {
			stoppers = append(stoppers, func() {
				trace.Stop()
				_ = f.Close()
			})
		}
	}

	return func() {
		// Stop in reverse order of start.
		for _, stop := range slices.Backward(stoppers) {
			stop()
		}
	}
}

// Track starts a wall-clock stopwatch for a named operation and returns a
// function that reports the elapsed time when called (typically via defer):
//
//	defer profiling.Track("export:disk")()
//
// When ABOX_TIMINGS is unset it is nearly free (one time.Now on entry) and emits
// nothing. When set, the returned function prints "abox: <name> took <duration>"
// to stderr and also logs it at debug level.
func Track(name string) func() {
	if os.Getenv("ABOX_TIMINGS") == "" {
		return func() {}
	}
	start := time.Now()
	return func() {
		elapsed := time.Since(start)
		fmt.Fprintf(os.Stderr, "abox: %s took %s\n", name, elapsed.Round(time.Millisecond))
		logging.Debug("timing", "op", name, "duration", elapsed)
	}
}
