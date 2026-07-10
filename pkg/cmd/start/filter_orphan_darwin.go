//go:build darwin

package start

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sandialabs/abox/internal/logging"
)

// pgrepLookup runs `pgrep -f <pattern>` and returns the matching PIDs. It is a
// package variable so tests can substitute a deterministic implementation
// without shelling out, mirroring the lookupComm seam in internal/vfkit.
var pgrepLookup = pgrepByPattern

// reclaimOrphanedFilterDaemon finds and terminates a filter daemon left running
// for this exact instance when the PID file was missing or stale. On macOS a
// daemon can outlive its PID-file bookkeeping (crash between spawn and PID-file
// write, or a buggy identity check having deleted the PID file while the process
// kept running and holding its UDP/TCP port). Launching a second daemon on top
// then dies on "address already in use" and the start path loops forever. This
// mirrors reclaimOrphanedHelper (internal/backend/vfkit/vm.go) for the filter
// daemons.
//
// Every candidate PID is independently re-verified with daemon.IsAboxProcess
// before being signaled: pgrep matches on the command line, which is not a
// trust boundary, so we never kill a PID we cannot positively confirm is ours.
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
		terminateOrphan(pid)
	}
}

// findOrphanedDaemonPIDs returns PIDs whose command line matches this instance's
// filter daemon (`abox <type> serve <name>`). The pattern anchors on the exact
// "<type> serve <name>" argv tail the start path spawns (see startFilter /
// startDaemon), so it cannot match another instance's daemon or an unrelated
// process that merely mentions the name.
func findOrphanedDaemonPIDs(name, daemonType string) ([]int, error) {
	// pgrep -f matches against the full argument vector. The tail
	// "<type> serve <name>" is what abox always passes (optionally preceded by
	// "--log-level X"), so it uniquely identifies this instance's daemon.
	pattern := fmt.Sprintf("%s serve %s", daemonType, name)
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
	logging.Warn("orphan daemon did not exit on SIGTERM, sending SIGKILL", "pid", pid)
	_ = proc.Kill()
}
