//go:build !unix

package procutil

import (
	"errors"
	"os"
)

// IsAlive makes a best-effort liveness probe on platforms without POSIX signals
// (Windows). os.FindProcess always succeeds on Windows, so it cannot by itself
// prove liveness; Signal(os.Kill) with a real send is destructive, so we only
// report the process as not-alive when FindProcess itself fails. This may
// over-report liveness on Windows, but abox's callers use the probe to avoid
// signalling a dead PID and to detect a crashed daemon — over-reporting is the
// safe direction (they will attempt and simply fail to signal a gone process).
func IsAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := os.FindProcess(pid)
	return err == nil
}

// TerminatePID asks the process to stop. Without POSIX SIGTERM, this falls back
// to Process.Kill (a forceful stop) on the located process.
func TerminatePID(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}

// KillPID forcefully stops the process. Without POSIX SIGKILL this is the same
// Process.Kill fallback as TerminatePID.
func KillPID(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}

// IsNotExistErr reports whether an error means the target process no longer
// exists. On platforms without POSIX signals this maps to os.ErrProcessDone.
func IsNotExistErr(err error) bool {
	return errors.Is(err, os.ErrProcessDone)
}
