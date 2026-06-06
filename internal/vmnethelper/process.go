//go:build darwin

package vmnethelper

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sandialabs/abox/internal/logging"
)

// startJSONReadTimeout bounds how long we wait for vmnet-helper's
// one-line start message. In the happy path the line appears within
// ~100ms; 5s gives ample headroom without letting silent hangs turn
// into UX bugs during `abox start`.
const startJSONReadTimeout = 5 * time.Second

// ChildSocketFD is the fd number the vmnet-helper child sees the socketpair
// end at: cmd.ExtraFiles[0] maps to fd 3 in the child. Callers must set
// HelperConfig.SocketFD to this value; Start enforces it.
const ChildSocketFD = 3

// Start launches vmnet-helper with cfg applied. The caller owns fdEnd
// (one half of a syscall.Socketpair); Start attaches it to
// cmd.ExtraFiles so the child sees it at fd 3. Start closes its
// parent-side view of fdEnd once the child has launched.
//
// Start reads one line of JSON from the helper's stdout (vmnet-helper
// emits its start message synchronously before entering its forwarding
// loop), parses it, resolves the bridge interface by scanning ifconfig
// for the gateway IP, writes the PID to cfg.PIDFile, and returns a
// fully populated *StartResult.
//
// On any error after the fork, Start signals the child and returns.
// On success, the child is reparented to launchd.
func Start(cfg HelperConfig, fdEnd *os.File) (*StartResult, error) {
	if cfg.BinaryPath == "" {
		return nil, errors.New("vmnethelper: BinaryPath is empty")
	}
	if cfg.SocketFD != ChildSocketFD {
		return nil, fmt.Errorf(
			"vmnethelper: SocketFD must be %d (ExtraFiles[0] maps to fd %d in the child), got %d",
			ChildSocketFD, ChildSocketFD, cfg.SocketFD,
		)
	}
	if fdEnd == nil {
		return nil, errors.New("vmnethelper: fdEnd is nil")
	}
	switch cfg.OperationMode {
	case ModeShared, ModeHost, ModeBridged:
	default:
		return nil, fmt.Errorf("vmnethelper: invalid OperationMode %q (want %s|%s|%s)",
			cfg.OperationMode, ModeShared, ModeHost, ModeBridged)
	}

	args := BuildArgs(cfg)
	logging.Debug("starting vmnet-helper",
		"name", cfg.Name,
		"args", strings.Join(args, " "),
	)

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create stdout pipe: %w", err)
	}

	var logFile *os.File
	if cfg.LogFile != "" {
		logFile, err = os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			_ = stdoutR.Close()
			_ = stdoutW.Close()
			return nil, fmt.Errorf("open vmnet-helper log file: %w", err)
		}
	}

	helper := exec.Command(args[0], args[1:]...)
	helper.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	helper.Stdout = stdoutW
	if logFile != nil {
		helper.Stderr = logFile
	}
	helper.ExtraFiles = []*os.File{fdEnd}

	if err := helper.Start(); err != nil {
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		if logFile != nil {
			_ = logFile.Close()
		}
		return nil, fmt.Errorf("start vmnet-helper: %w", err)
	}

	// After a successful fork, the child inherited stdoutW and fdEnd;
	// close our parent-side copies so reads on stdoutR see EOF when
	// the child exits. logFile intentionally stays open — matches
	// vfkit's pattern; the OS closes it when the helper exits.
	_ = stdoutW.Close()
	_ = fdEnd.Close()

	pid := helper.Process.Pid

	// Read one line of JSON with a deadline. Pipes support SetReadDeadline
	// since Go 1.10 (via poller). Closing stdoutR after the read relies
	// on vmnet-helper's "emit once at startup" stdout contract — it won't
	// write again, so no SIGPIPE risk.
	line, readErr := readLineWithDeadline(stdoutR, startJSONReadTimeout)
	_ = stdoutR.Close()
	if readErr != nil {
		killChild(helper)
		return nil, fmt.Errorf("read vmnet-helper start JSON: %w", readErr)
	}

	sj, err := parseStartJSON(line)
	if err != nil {
		killChild(helper)
		return nil, err
	}

	bridge, err := BridgeInterfaceForGateway(sj.StartAddress)
	if err != nil {
		killChild(helper)
		return nil, fmt.Errorf("resolve bridge interface: %w", err)
	}

	if cfg.PIDFile != "" {
		if err := os.WriteFile(cfg.PIDFile, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
			killChild(helper)
			return nil, fmt.Errorf("write vmnet-helper PID file: %w", err)
		}
	}

	logging.Debug("vmnet-helper started",
		"name", cfg.Name,
		"pid", pid,
		"bridge", bridge,
		"gateway", sj.StartAddress,
	)

	// Detach — launchd reaps the child when it exits.
	_ = helper.Process.Release()

	return &StartResult{
		PID:             pid,
		StartAddress:    sj.StartAddress,
		EndAddress:      sj.EndAddress,
		SubnetMask:      sj.SubnetMask,
		MTU:             sj.MTU,
		MAC:             sj.MAC,
		InterfaceID:     sj.InterfaceID,
		NAT66Prefix:     sj.NAT66Prefix,
		BridgeInterface: bridge,
	}, nil
}

// Stop sends SIGTERM to the vmnet-helper PID from pidFile, waits up to
// 5 seconds for exit, then SIGKILLs. Removes pidFile on success.
func Stop(pidFile string) error {
	pid, err := ReadPID(pidFile)
	if err != nil {
		return err
	}

	if !isHelperProcess(pid) {
		logging.Warn("PID is not a vmnet-helper process, cleaning up stale PID file", "pid", pid)
		_ = os.Remove(pidFile)
		return nil
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find vmnet-helper process %d: %w", pid, err)
	}

	logging.Debug("sending SIGTERM to vmnet-helper", "pid", pid)
	if sigErr := proc.Signal(syscall.SIGTERM); sigErr != nil {
		logging.Debug("vmnet-helper process already exited", "pid", pid, "error", sigErr)
		_ = os.Remove(pidFile)
		return nil
	}

	for range 50 {
		time.Sleep(100 * time.Millisecond)
		if !processAlive(proc) {
			_ = os.Remove(pidFile)
			return nil
		}
	}

	logging.Warn("vmnet-helper did not stop gracefully, sending SIGKILL", "pid", pid)
	if err := proc.Kill(); err != nil {
		logging.Warn("failed to SIGKILL vmnet-helper", "pid", pid, "error", err)
	}

	_ = os.Remove(pidFile)
	return nil
}

// ForceStop sends SIGKILL to the vmnet-helper process immediately.
func ForceStop(pidFile string) error {
	pid, err := ReadPID(pidFile)
	if err != nil {
		return err
	}

	if !isHelperProcess(pid) {
		logging.Warn("PID is not a vmnet-helper process, cleaning up stale PID file", "pid", pid)
		_ = os.Remove(pidFile)
		return nil
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find vmnet-helper process %d: %w", pid, err)
	}

	logging.Debug("sending SIGKILL to vmnet-helper", "pid", pid)
	if err := proc.Kill(); err != nil {
		logging.Warn("failed to SIGKILL vmnet-helper", "pid", pid, "error", err)
	}

	_ = os.Remove(pidFile)
	return nil
}

// IsRunning reads pidFile and checks whether the referenced process is
// alive and looks like a vmnet-helper (or its sudo parent on macOS 15).
func IsRunning(pidFile string) bool {
	pid, err := ReadPID(pidFile)
	if err != nil {
		return false
	}
	if !isHelperProcess(pid) {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

// ReadPID reads and validates a PID from a PID file.
func ReadPID(pidFile string) (int, error) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, fmt.Errorf("read PID file %s: %w", pidFile, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("invalid PID in %s: %q", pidFile, strings.TrimSpace(string(data)))
	}
	return pid, nil
}

// CleanupPIDFile removes a PID file if the referenced process is dead.
func CleanupPIDFile(pidFile string) error {
	if IsRunning(pidFile) {
		return fmt.Errorf("vmnet-helper process is still running (PID file: %s)", pidFile)
	}
	if err := os.Remove(pidFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale PID file %s: %w", pidFile, err)
	}
	return nil
}

// processAlive checks if proc is still running via signal 0.
func processAlive(proc *os.Process) bool {
	return proc.Signal(syscall.Signal(0)) == nil
}

// isHelperProcess checks that a PID's comm is "vmnet-helper" or "sudo"
// via `ps -p <pid> -o comm=`. Two names because on macOS 15 we spawn
// `sudo -n vmnet-helper …` and the recorded PID is sudo's (which
// propagates SIGTERM to its child). On macOS 26+ the recorded PID is
// vmnet-helper directly.
func isHelperProcess(pid int) bool {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return false
	}
	comm := strings.TrimSpace(string(out))
	return strings.Contains(comm, "vmnet-helper") || strings.HasSuffix(comm, "/"+cmdSudo) || comm == cmdSudo
}

// killChild is a best-effort SIGKILL for cleanup paths in Start where
// we've spawned the child but can't complete initialization.
func killChild(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	// Release so Go's os/exec doesn't linger holding the process handle.
	_ = cmd.Process.Release()
}

// readLineWithDeadline reads up to the first '\n' from r, subject to
// deadline. Works on pipe FDs because *os.File supports SetReadDeadline
// on poller-backed descriptors.
func readLineWithDeadline(r *os.File, deadline time.Duration) ([]byte, error) {
	if err := r.SetReadDeadline(time.Now().Add(deadline)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}
	// Use bufio.Scanner so we stop at the newline instead of reading
	// until EOF (vmnet-helper keeps the stdout fd open after the start
	// message until it exits).
	scanner := bufio.NewScanner(r)
	// Bump the buffer ceiling modestly — vmnet-helper's JSON line is
	// well under 4K, but leave headroom for future fields.
	scanner.Buffer(make([]byte, 0, 4096), 64*1024)
	if scanner.Scan() {
		// Bytes() is valid only until the next Scan call; the caller
		// copies immediately via string(firstLine) in parseStartJSON.
		return scanner.Bytes(), nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("vmnet-helper closed stdout before emitting start message")
}
