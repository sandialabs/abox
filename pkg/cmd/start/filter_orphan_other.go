//go:build !darwin

package start

import "io"

// reclaimOrphanedFilterDaemon is a no-op off macOS. On Linux the /proc-based
// identity check (daemon.IsAboxProcess) does not suffer the darwin failure mode
// where $TMPDIR purges silently orphan a live daemon from its PID file, so the
// stale-file path in checkAlreadyRunning is sufficient and no out-of-band process
// discovery is needed. Other platforms have no filter daemons to reclaim.
func reclaimOrphanedFilterDaemon(_ io.Writer, _, _ string) {}
