//go:build darwin

package start

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sandialabs/abox/internal/daemon"
	"github.com/sandialabs/abox/internal/logging"
)

// pgrepLookup runs `pgrep -f <pattern>` and returns the matching PIDs. It is a
// package variable so tests can substitute a deterministic implementation
// without shelling out.
var pgrepLookup = pgrepByPattern

// isAboxProcessFn re-verifies a candidate PID's identity. Seam for tests.
var isAboxProcessFn = daemon.VerifyAboxProcess

// terminateOrphanFn signals a confirmed-orphan PID. A package variable so tests
// can assert exactly which PIDs get signaled (and that unverifiable ones do not).
var terminateOrphanFn = terminateOrphan

// reclaimOrphanedFilterDaemon finds and terminates a daemon left running for this
// exact instance when its PID file was missing or stale. On macOS the DNS/HTTP/
// monitor sockets and PID files live under $TMPDIR, which the OS purges after a
// few idle days: the daemon keeps running and holding its port, but the PID-file
// bookkeeping is gone, so checkAlreadyRunning sees "not running", cleans up
// nothing useful, and the fresh daemon then dies on "address already in use" —
// wedging `abox start` with no CLI recovery. This mirrors reclaimOrphanedHelper
// (internal/backend/vfkit/vm.go) for the filter daemons.
//
// It only runs after checkAlreadyRunning has already reported the daemon is not
// alive per its PID file, so a healthy tracked daemon is never a candidate.
// Every candidate PID is independently re-verified with daemon.VerifyAboxProcess
// before being signaled: pgrep matches on the command line, which is not a trust
// boundary, so we never kill a PID we cannot positively confirm is ours.
func reclaimOrphanedFilterDaemon(w io.Writer, name, daemonType string) {
	if w == nil {
		w = io.Discard
	}
	pids, err := findOrphanedDaemonPIDs(name, daemonType)
	if err != nil {
		logging.Debug("orphan daemon discovery failed", "type", daemonType, "instance", name, "error", err)
		return
	}
	self := os.Getpid()
	for _, pid := range pids {
		if pid == self || pid <= 1 {
			continue
		}
		isAbox, idErr := isAboxProcessFn(pid)
		if idErr != nil {
			logging.Warn("found candidate orphan daemon but could not verify identity, leaving it",
				"type", daemonType, "instance", name, "pid", pid, "error", idErr)
			continue
		}
		if !isAbox {
			continue
		}
		fmt.Fprintf(w, "  reclaiming orphaned %s daemon (pid %d) from a previous run...\n", daemonType, pid)
		logging.Warn("reclaiming orphaned filter daemon from a previous crash",
			"type", daemonType, "instance", name, "pid", pid)
		terminateOrphanFn(pid)
	}
}

// findOrphanedDaemonPIDs returns PIDs whose command line matches this instance's
// daemon (`abox [--log-level X] <type> serve <name>`). The pattern anchors the
// instance name to the END of the argument vector — the name is always the last
// arg the start path passes — so it cannot match a sibling instance whose name
// merely has this one as a prefix (e.g. reclaiming "dev" must not kill "dev2").
// The name is regexp-escaped defensively even though instance names are already
// validated to a safe character set.
func findOrphanedDaemonPIDs(name, daemonType string) ([]int, error) {
	pattern := fmt.Sprintf("%s serve %s$", daemonType, regexp.QuoteMeta(name))
	return pgrepLookup(pattern)
}

// pgrepByPattern runs `pgrep -f <pattern>` and parses the PID list. A non-zero
// exit with no output (pgrep's "no matches" status 1) is reported as an empty
// result, not an error.
func pgrepByPattern(pattern string) ([]int, error) {
	out, err := exec.Command("pgrep", "-f", pattern).Output()
	trimmed := strings.TrimSpace(string(out))
	if err != nil {
		// pgrep exits 1 when there are no matches; that is not a failure.
		if trimmed == "" {
			return nil, nil
		}
		return nil, err
	}
	var pids []int
	for line := range strings.FieldsSeq(trimmed) {
		if pid, perr := strconv.Atoi(line); perr == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// terminateOrphan sends SIGTERM, waits briefly, then SIGKILL if still alive.
// Matches the graceful-then-force style of reclaimOrphanedHelper.
func terminateOrphan(pid int) {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		logging.Warn("failed to SIGTERM orphan daemon, attempting SIGKILL", "pid", pid, "error", err)
		_ = proc.Kill()
		return
	}
	for range 10 {
		time.Sleep(100 * time.Millisecond)
		if proc.Signal(syscall.Signal(0)) != nil {
			return // gone
		}
	}
	// PID-recycle guard: the daemon may have exited during the wait and the OS may
	// have reused its PID for an unrelated process. Re-confirm identity before the
	// escalating SIGKILL so we uphold the "never kill a PID we cannot positively
	// confirm is ours" invariant (see reclaimOrphanedFilterDaemon) through force-kill.
	if isAbox, err := isAboxProcessFn(pid); err != nil || !isAbox {
		logging.Warn("orphan daemon PID no longer confirms as ours; skipping SIGKILL",
			"pid", pid, "stillAbox", isAbox, "error", err)
		return
	}
	logging.Warn("orphan daemon did not exit on SIGTERM, sending SIGKILL", "pid", pid)
	_ = proc.Kill()
}
