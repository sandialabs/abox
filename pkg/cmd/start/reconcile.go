package start

import (
	"fmt"
	"io"
	"os"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/mountutil"
	fwdshared "github.com/sandialabs/abox/pkg/cmd/forward/shared"
	mountshared "github.com/sandialabs/abox/pkg/cmd/mount/shared"
)

// Seams for testing reconcileUserResources in isolation: the real functions
// shell out to fusermount/sshfs/ssh and scan the process table, so tests swap
// these for fakes to exercise the state machine. Matches the var-seam pattern
// used for recoverDaemons in start.go.
var (
	mountStateFn        = mountutil.State
	unmountFn           = mountutil.Unmount
	mountFn             = mountshared.Mount
	findLiveTunnelPIDFn = fwdshared.FindLiveTunnelPID
	startTunnelFn       = fwdshared.StartTunnel
)

// reconcileUserResources re-establishes the user-created SSHFS mounts
// (mounts.json) and SSH port forwards (forwards.json) recorded for the
// instance. `abox stop` leaves their sshfs/ssh processes to die with the VM, so
// after a restart the records point at dead PIDs and the mount points are stale
// ENOTCONN FUSE endpoints.
//
// Every failure is a warning, never a fatal error: the instance itself started
// fine, and a record is always KEPT on failure — dropping it would lose the
// user's intent, and `abox mount remove` / `abox forward remove` remain the
// explicit cleanup paths.
func reconcileUserResources(w io.Writer, inst *config.Instance, paths *config.Paths) {
	reconcileMounts(w, inst, paths)
	reconcileForwards(w, inst, paths)
}

// reconcileMounts walks the recorded mounts: a live mount is left alone, a
// stale (dead-endpoint) mount is force/lazy-unmounted first, and anything not
// mounted is re-established with its recorded flags.
//
// macOS note: a stale fuse-t mount may surface a different errno than ENOTCONN
// from lstat, in which case it reads as StateNotMounted here; the remount
// attempt then fails fast against the still-occupied mount point and is
// reported as a warning — never a fatal error.
func reconcileMounts(w io.Writer, inst *config.Instance, paths *config.Paths) {
	mounts, err := mountshared.GetMounts(paths.Instance)
	if err != nil {
		fmt.Fprintf(w, "  Warning: could not read mount records: %v\n", err)
		return
	}

	for _, m := range mounts {
		state, err := mountStateFn(m.LocalPath)
		if err != nil {
			fmt.Fprintf(w, "  Warning: could not check mount %s: %v\n", m.LocalPath, err)
			continue
		}
		switch state {
		case mountutil.StateMounted:
			continue // healthy, leave it alone
		case mountutil.StateStale:
			// Dead FUSE endpoint: detach it (force => lazy on Linux) before
			// mounting the path again.
			if err := unmountFn(m.LocalPath, true); err != nil {
				fmt.Fprintf(w, "  Warning: could not unmount stale mount %s: %v\n", m.LocalPath, err)
				continue
			}
		case mountutil.StateNotMounted:
			// Nothing to clean up; fall through to remount.
		}

		// Recreate the mount point if needed (0o700 restricts to owner, as
		// mount add does).
		if err := os.MkdirAll(m.LocalPath, 0o700); err != nil {
			fmt.Fprintf(w, "  Warning: could not create mount point %s: %v\n", m.LocalPath, err)
			continue
		}

		if err := mountFn(paths, inst.GetUser(), inst.IPAddress, m); err != nil {
			// Keep the record: the user asked for this mount, and `abox mount
			// remove` is the explicit way to retire it.
			fmt.Fprintf(w, "  Warning: could not re-establish mount %s: %v\n", m.LocalPath, err)
			continue
		}
		fmt.Fprintf(w, "  Re-established mount %s:%s at %s\n", inst.Name, m.RemotePath, m.LocalPath)
	}
}

// reconcileForwards walks the recorded port forwards: a tunnel found live by
// cmdline match is kept (its recorded PID corrected if it moved), and a dead
// one is restarted with a fresh PID recorded.
func reconcileForwards(w io.Writer, inst *config.Instance, paths *config.Paths) {
	forwards, err := fwdshared.LoadForwards(paths.Instance)
	if err != nil {
		fmt.Fprintf(w, "  Warning: could not read forward records: %v\n", err)
		return
	}

	for _, f := range forwards.Forwards {
		if pid, ok := findLiveTunnelPIDFn(inst.GetUser(), inst.IPAddress, f); ok {
			if pid == f.PID {
				continue // tunnel alive and record accurate
			}
			// Tunnel alive under a different PID (record went stale).
			if err := fwdshared.UpdateForwardPID(paths.Instance, f.HostPort, pid); err != nil {
				fmt.Fprintf(w, "  Warning: could not update forward record for host port %d: %v\n", f.HostPort, err)
			}
			continue
		}

		pid, err := startTunnelFn(paths, inst.GetUser(), inst.IPAddress, f)
		if err != nil {
			// Keep the record: `abox forward remove` is the explicit cleanup.
			fmt.Fprintf(w, "  Warning: could not re-establish forward for host port %d: %v\n", f.HostPort, err)
			continue
		}
		if err := fwdshared.UpdateForwardPID(paths.Instance, f.HostPort, pid); err != nil {
			fmt.Fprintf(w, "  Warning: could not update forward record for host port %d: %v\n", f.HostPort, err)
		}
		if f.Reverse {
			fmt.Fprintf(w, "  Re-established reverse forward guest:%d -> host:%d (pid %d)\n", f.GuestPort, f.HostPort, pid)
		} else {
			fmt.Fprintf(w, "  Re-established forward localhost:%d -> guest:%d (pid %d)\n", f.HostPort, f.GuestPort, pid)
		}
	}
}

// warnSkippedReconcile tells the user their recorded mounts/forwards were NOT
// re-established because the guest never became reachable over SSH — attempting
// sshfs/ssh against an unreachable guest would hang the start. Silent when
// there is nothing recorded.
func warnSkippedReconcile(w io.Writer, paths *config.Paths) {
	mounts, mErr := mountshared.GetMounts(paths.Instance)
	forwards, fErr := fwdshared.LoadForwards(paths.Instance)
	// An unreadable records file counts as "may have records": a spurious
	// heads-up beats silently skipping re-establishment.
	if mErr == nil && fErr == nil && len(mounts)+len(forwards.Forwards) == 0 {
		return
	}
	fmt.Fprintln(w, "  Warning: instance not reachable over SSH; skipping re-establishment of recorded mounts/forwards")
}
