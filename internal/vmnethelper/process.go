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
	"time"

	"github.com/sandialabs/abox/internal/childproc"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/procutil"
)

// startJSONReadTimeout bounds how long we wait for vmnet-helper's
// one-line start message. In the happy path the line appears within
// ~100ms; 5s gives ample headroom without letting silent hangs turn
// into UX bugs during `abox start`.
const startJSONReadTimeout = 5 * time.Second

// logTailLines is how many trailing vmnet-helper.log lines to surface when the
// start handshake fails, enough to show the fatal error (e.g. a sudo/NOPASSWD
// rejection or a socket bind failure) without dumping the whole log.
const logTailLines = 10

// openHelperIO creates the stdout pipe the parent reads the start-JSON from and,
// when cfg.LogFile is set, opens the append-mode log file used for the helper's
// stderr. On any error it closes whatever it already opened before returning, so
// the caller never leaks a half-open descriptor.
func openHelperIO(cfg HelperConfig) (stdoutR, stdoutW, logFile *os.File, err error) {
	stdoutR, stdoutW, err = os.Pipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create stdout pipe: %w", err)
	}
	if cfg.LogFile != "" {
		logFile, err = os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			_ = stdoutR.Close()
			_ = stdoutW.Close()
			return nil, nil, nil, fmt.Errorf("open vmnet-helper log file: %w", err)
		}
	}
	return stdoutR, stdoutW, logFile, nil
}

// Start launches vmnet-helper with cfg applied. The helper binds a unix
// datagram socket at cfg.SocketPath (--socket mode) and waits for the VMM to
// connect; no file descriptor is passed to the child, so nothing has to survive
// the sudo boundary (sudo's closefrom would otherwise strip an inherited fd).
//
// Start reads one line of JSON from the helper's stdout (vmnet-helper
// emits its start message synchronously before entering its forwarding
// loop), parses it, resolves the bridge interface by scanning ifconfig
// for the gateway IP, writes the PID to cfg.PIDFile, and returns a
// fully populated *StartResult.
//
// On any error after the fork, Start signals the child and returns.
// On success, the child is reparented to launchd.
func Start(cfg HelperConfig) (*StartResult, error) {
	if cfg.BinaryPath == "" {
		return nil, errors.New("vmnethelper: BinaryPath is empty")
	}
	if cfg.SocketPath == "" {
		return nil, errors.New("vmnethelper: SocketPath is empty")
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

	stdoutR, stdoutW, logFile, err := openHelperIO(cfg)
	if err != nil {
		return nil, err
	}

	helper := exec.Command(args[0], args[1:]...)
	procutil.Detach(helper)
	helper.Stdout = stdoutW
	if logFile != nil {
		helper.Stderr = logFile
	}

	if err := helper.Start(); err != nil {
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		if logFile != nil {
			_ = logFile.Close()
		}
		return nil, fmt.Errorf("start vmnet-helper: %w", err)
	}

	// After a successful fork, the child inherited stdoutW; close our
	// parent-side copy so reads on stdoutR see EOF when the child exits.
	// logFile intentionally stays open — matches vfkit's pattern; the OS
	// closes it when the helper exits.
	_ = stdoutW.Close()

	pid := helper.Process.Pid

	// abort kills the freshly-forked child and removes any PID file we wrote;
	// used on every post-fork initialization failure so we never leave a running
	// helper with a stale (or partially written) PID file pointing at it.
	abort := func() {
		killChild(helper)
		if cfg.PIDFile != "" {
			_ = os.Remove(cfg.PIDFile)
		}
		// The child is being killed, so close our parent-side log fd too.
		// (The success path intentionally leaves logFile open — inherited by
		// the detached child and closed by the OS when the helper exits.)
		if logFile != nil {
			_ = logFile.Close()
		}
	}

	// Write the PID file immediately after the fork, before the fallible init
	// steps below. If any of them fail — or abox crashes mid-init — the helper
	// is already running, and on macOS ≤25 it is root-owned; without a
	// discoverable PID file reclaimOrphanedHelper could never find it and the
	// leaked helper would hold the pinned subnet forever. The failure paths
	// below remove the file via abort(); it is kept only on success.
	if cfg.PIDFile != "" {
		if err := os.WriteFile(cfg.PIDFile, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
			abort()
			return nil, fmt.Errorf("write vmnet-helper PID file: %w", err)
		}
	}

	// Read one line of JSON with a deadline. Pipes support SetReadDeadline
	// since Go 1.10 (via poller). Closing stdoutR after the read relies
	// on vmnet-helper's "emit once at startup" stdout contract — it won't
	// write again, so no SIGPIPE risk.
	line, readErr := readLineWithDeadline(stdoutR, startJSONReadTimeout)
	_ = stdoutR.Close()
	if readErr != nil {
		abort()
		// A missing start line usually means the helper died before serving:
		// a sudo/NOPASSWD rejection or a socket bind failure. Surface the log
		// tail so the cause is actionable rather than an opaque read error.
		if tail := logTail(cfg.LogFile, logTailLines); tail != "" {
			return nil, fmt.Errorf("read vmnet-helper start JSON: %w\nvmnet-helper.log:\n%s", readErr, tail)
		}
		return nil, fmt.Errorf("read vmnet-helper start JSON: %w", readErr)
	}

	sj, err := parseStartJSON(line)
	if err != nil {
		abort()
		return nil, err
	}

	bridge, err := BridgeInterfaceForGateway(sj.StartAddress)
	if err != nil {
		abort()
		return nil, fmt.Errorf("resolve bridge interface: %w", err)
	}

	logging.Debug("vmnet-helper started",
		"name", cfg.Name,
		"pid", pid,
		"bridge", bridge,
		"gateway", sj.StartAddress,
	)

	// Audit the spawn of this root-owned host-networking process (it creates and
	// pins a vmnet interface/subnet). This is a privileged host-state mutation, so
	// its lifecycle gets a first-class audit record rather than only Debug lines.
	logging.Audit("vmnet-helper.start",
		"name", cfg.Name,
		"pid", pid,
		"mode", cfg.OperationMode,
		"socket", cfg.SocketPath,
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
	pid, _ := supervisor.ReadPID(pidFile)
	err := supervisor.Stop(pidFile)
	auditTermination("vmnet-helper.stop", pid, err)
	return err
}

// ForceStop sends SIGKILL to the vmnet-helper process immediately.
func ForceStop(pidFile string) error {
	pid, _ := supervisor.ReadPID(pidFile)
	err := supervisor.ForceStop(pidFile)
	auditTermination("vmnet-helper.force-stop", pid, err)
	return err
}

// auditTermination records the outcome of a vmnet-helper termination request so
// the root-owned process's teardown is traceable in the audit trail. pid may be 0
// if the PID file was already gone (best-effort).
func auditTermination(event string, pid int, err error) {
	if err != nil {
		logging.Audit(event, "pid", pid, "result", "error", "error", err.Error())
		return
	}
	logging.Audit(event, "pid", pid, "result", "success")
}

// IsRunning reads pidFile and checks whether the referenced process is
// alive and looks like a vmnet-helper (or its sudo parent on macOS 15).
func IsRunning(pidFile string) bool {
	return supervisor.IsRunning(pidFile)
}

// ReadPID reads and validates a PID from a PID file.
func ReadPID(pidFile string) (int, error) {
	return supervisor.ReadPID(pidFile)
}

// CleanupPIDFile removes a PID file if the referenced process is dead.
func CleanupPIDFile(pidFile string) error {
	return supervisor.CleanupPIDFile(pidFile)
}

// supervisor owns the shared PID-file/comm-verification lifecycle. isHelperProcess
// is the comm guard that keeps Stop/ForceStop from signalling a reused PID. The
// Terminate/Kill overrides route through signalHelper so that on macOS versions
// where the helper is launched via sudo (NeedsSudo), the root-owned PID is
// signalled with `sudo -n kill` rather than a direct syscall that would EPERM.
var supervisor = childproc.Supervisor{
	Name:      "vmnet-helper",
	Matches:   isHelperProcess,
	Terminate: func(pid int) error { return signalHelper(pid, sigTERM) },
	Kill:      func(pid int) error { return signalHelper(pid, sigKILL) },
}

// kill(1) signal-name arguments (portable across macOS versions; kill maps the
// name to the number). Passed to `kill -<name>`.
const (
	sigTERM = "TERM"
	sigKILL = "KILL"
)

// interactiveSignaling gates the interactive `sudo kill` fallback in signalHelper.
// It defaults to false so paths that must never block on a password prompt — most
// importantly reclaimOrphanedHelper during `abox start` — stay non-interactive and
// best-effort. The stop/remove/down commands opt in via SetInteractiveSignaling based
// on whether they are attached to a terminal.
var interactiveSignaling bool

// interactiveAttempted records that signalHelper has already put up an interactive
// prompt in this process, so it never prompts twice. childproc.Supervisor.Stop sends
// SIGTERM, polls, then escalates to SIGKILL; without this guard a declined SIGTERM
// prompt (no cached credential) would trigger a second prompt on the SIGKILL. A
// successful prompt caches the sudo credential, so the SIGKILL's `sudo -n` succeeds
// silently and this guard is not consulted.
var interactiveAttempted bool

// SetInteractiveSignaling controls whether signalHelper may fall back to an
// interactive `sudo kill` (prompting for a password) when the non-interactive
// `sudo -n kill` is refused. Commands enable it only when attached to a terminal.
func SetInteractiveSignaling(v bool) { interactiveSignaling = v }

// signalHelper delivers a signal to the vmnet-helper PID.
//
// On macOS 26+ (!NeedsSudo) the helper runs as the invoking user and is signalled
// with a direct syscall via procutil.
//
// On macOS ≤15 the recorded PID is root-owned (the helper was launched via sudo), so
// abox cannot signal it directly. It first tries `sudo -n kill`, which succeeds
// silently if a passwordless sudoers entry permits kill or sudo's credential is
// already cached. If that is refused and interactive signaling is enabled (an
// interactive stop/remove/down), it falls back once to an interactive `sudo kill`,
// prompting for the password — the same escalation the pf-anchor teardown performs,
// and cheaper than requiring a broad passwordless-kill sudoers grant. When no terminal
// is attached (or a prompt was already shown), it returns an actionable error rather
// than hanging on a password prompt.
var signalHelper = func(pid int, sig string) error {
	if !NeedsSudo() {
		if sig == sigKILL {
			return procutil.KillPID(pid)
		}
		return procutil.TerminatePID(pid)
	}

	// Fast path: passwordless sudoers entry for kill, or a cached credential.
	out, err := exec.Command(cmdSudo, "-n", "kill", "-"+sig, strconv.Itoa(pid)).CombinedOutput()
	if err == nil {
		return nil
	}
	nonInteractiveErr := fmt.Errorf("sudo -n kill -%s %d: %s: %w", sig, pid, strings.TrimSpace(string(out)), err)

	if !interactiveSignaling || interactiveAttempted {
		// Best-effort: cannot signal a root-owned helper without a password here.
		return fmt.Errorf("%w (run `abox stop` from an interactive terminal to authorize)", nonInteractiveErr)
	}

	// Interactive fallback: prompt once. A success caches the credential so any
	// follow-up signal (e.g. the SIGKILL escalation) takes the fast path above.
	interactiveAttempted = true
	fmt.Fprintln(os.Stderr, "Requesting elevated privileges to stop vmnet-helper...")
	cmd := exec.Command(cmdSudo, "kill", "-"+sig, strconv.Itoa(pid))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stderr // keep abox's stdout clean; sudo's prompt goes to stderr
	cmd.Stderr = os.Stderr
	if runErr := cmd.Run(); runErr != nil {
		return fmt.Errorf("sudo kill -%s %d: %w", sig, pid, runErr)
	}
	return nil
}

// lookupComm returns the command name (comm) of a PID. It is a package
// variable so tests can substitute a deterministic implementation without
// shelling out to ps or depending on what processes happen to be running.
// It defaults to the real ps-based lookup.
var lookupComm = childproc.LookupComm

// lookupCmdline returns the full command line (argv) of a PID. Like lookupComm
// it is a package variable so tests can substitute a deterministic result.
var lookupCmdline = childproc.LookupCmdline

// isHelperProcess reports whether a PID is (still) our vmnet-helper.
//
// On macOS 26+ the recorded PID is vmnet-helper itself, so a comm match is
// definitive. On macOS ≤15 we spawn `sudo -n vmnet-helper …` and the recorded
// PID is sudo's (it forwards SIGTERM to its child), so we must also accept a
// "sudo" comm — but "sudo" is a generic name shared by every sudo invocation on
// the host. If our sudo parent has exited and its PID was recycled by an
// unrelated `sudo`, a bare comm match would let Stop/ForceStop signal-kill that
// innocent (root) process. So the sudo branch additionally requires the
// process's argv to actually reference vmnet-helper before we treat it as ours.
func isHelperProcess(pid int) bool {
	comm, err := lookupComm(pid)
	if err != nil {
		return false
	}
	if strings.Contains(comm, "vmnet-helper") {
		return true
	}
	if comm == cmdSudo || strings.HasSuffix(comm, "/"+cmdSudo) {
		cmdline, err := lookupCmdline(pid)
		if err != nil {
			return false
		}
		return strings.Contains(cmdline, "vmnet-helper")
	}
	return false
}

// killChild is a best-effort kill for cleanup paths in Start where we've
// spawned the child but can't complete initialization.
func killChild(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	// Audit the abort-path kill of a freshly-spawned root-owned helper (a failed
	// start still left a running process holding a vmnet interface until this).
	logging.Audit("vmnet-helper.kill", "pid", pid, "reason", "start-abort")
	if NeedsSudo() {
		// macOS ≤25: the recorded process is the root-owned `sudo` child. A
		// direct cmd.Process.Kill() would EPERM (silently), and cmd.Process.Wait()
		// would then block forever because sudo never dies — hanging `abox start`
		// and leaking the root helper. Signal via `sudo -n kill` instead; SIGTERM
		// lets sudo forward the signal to the helper for a clean exit. We cannot
		// reap a root process, so Release Go's handle rather than Wait on it.
		_ = signalHelper(pid, sigTERM)
		_ = cmd.Process.Release()
		return
	}
	// macOS 26+: the helper runs as the invoking user; SIGKILL it directly and
	// reap the zombie. The child is dying from the Kill above, so Wait does not
	// block. Wait also releases Go's process handle, so no Release is needed.
	_ = procutil.KillPID(pid)
	_, _ = cmd.Process.Wait()
}

// logTail returns up to the last n lines of the named file, for surfacing in
// error messages when the start handshake fails. Returns "" if the file can't
// be read or is empty; callers treat an empty tail as "nothing to show".
func logTail(path string, n int) string {
	if path == "" || n <= 0 {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		return ""
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
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
