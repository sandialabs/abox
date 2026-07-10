//go:build linux

package start

import "io"

// reclaimOrphanedFilterDaemon is a no-op on Linux. The /proc-based identity
// check (daemon.IsAboxProcess) does not suffer the darwin failure mode that
// silently deletes a live daemon's PID file, so the stale-file path in
// checkAlreadyRunning is sufficient and no out-of-band process discovery is
// needed.
func reclaimOrphanedFilterDaemon(_ io.Writer, _, _ string) {}
