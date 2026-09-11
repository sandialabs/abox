//go:build unix

// Package procutil provides small OS-capability seams for process control
// (liveness probes, termination, exec-replacement) so callers depend on the
// capability rather than a Linux-specific syscall.
package procutil

import (
	"errors"
	"syscall"
)

// IsAlive reports whether a process with the given PID currently exists. It uses
// the POSIX "signal 0" probe, which performs the existence/permission check
// without delivering a signal. A non-positive pid is never alive.
//
// EPERM counts as alive: the process exists but is owned by another user (e.g. a
// root-owned helper spawned via sudo) so this process may not signal it. Only
// ESRCH — no such process — means truly dead. Reporting an unsignalable-but-live
// process as alive is what lets orphan detection see a root-owned vmnet-helper on
// macOS ≤15 instead of mistaking it for gone and leaking it.
func IsAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// TerminatePID sends SIGTERM to the given PID, asking it to shut down gracefully.
func TerminatePID(pid int) error {
	return syscall.Kill(pid, syscall.SIGTERM)
}

// KillPID sends SIGKILL to the given PID — a forceful, uncatchable stop.
func KillPID(pid int) error {
	return syscall.Kill(pid, syscall.SIGKILL)
}

// IsNotExistErr reports whether an error from TerminatePID/KillPID means the
// target process does not exist (ESRCH), as opposed to existing-but-unsignalable
// (EPERM) or an unrelated failure. Callers use it to distinguish "already gone"
// (safe to clean up) from "could not signal" (do not assume gone).
func IsNotExistErr(err error) bool {
	return errors.Is(err, syscall.ESRCH)
}
