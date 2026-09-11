//go:build darwin

package vmnethelper

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func withLookupComm(t *testing.T, fn func(pid int) (string, error)) {
	t.Helper()
	prev := lookupComm
	lookupComm = fn
	t.Cleanup(func() { lookupComm = prev })
}

func withLookupCmdline(t *testing.T, fn func(pid int) (string, error)) {
	t.Helper()
	prev := lookupCmdline
	lookupCmdline = fn
	t.Cleanup(func() { lookupCmdline = prev })
}

// forceMacOSVersion pins the NeedsSudo probe to a specific product version so
// tests exercising the sudo vs direct-syscall paths are deterministic on any
// host (the probe is memoised via a sync.Once, so it must be reset).
func forceMacOSVersion(t *testing.T, version string) {
	t.Helper()
	resetSudoProbe()
	prev := productVersionFn
	productVersionFn = func() (string, error) { return version, nil }
	t.Cleanup(func() {
		productVersionFn = prev
		resetSudoProbe()
	})
}

// withSignalHelper swaps the signalHelper seam so a test can observe the
// (pid, sig) delivered without actually signalling (or shelling out to sudo).
func withSignalHelper(t *testing.T, fn func(pid int, sig string) error) {
	t.Helper()
	prev := signalHelper
	signalHelper = fn
	t.Cleanup(func() { signalHelper = prev })
}

// withInteractiveSignaling sets the interactiveSignaling gate and resets the
// interactiveAttempted guard for a test, restoring both afterwards. These are
// package globals so they must be reset between cases.
func withInteractiveSignaling(t *testing.T, enabled bool) {
	t.Helper()
	prevEnabled, prevAttempted := interactiveSignaling, interactiveAttempted
	interactiveSignaling = enabled
	interactiveAttempted = false
	t.Cleanup(func() {
		interactiveSignaling = prevEnabled
		interactiveAttempted = prevAttempted
	})
}

// fakeSudo installs a stub `sudo` on PATH so tests exercise the real signalHelper
// without escalating. The stub logs each invocation's args (one line per call) to
// the returned path. `-n` invocations exit 0 when nOK is true, else fail with a
// "password is required" message; interactive invocations (no `-n`) exit 0 when
// interactiveOK is true, else fail (simulating a declined/incorrect password).
func fakeSudo(t *testing.T, nOK, interactiveOK bool) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "sudo.log")
	nExit, iExit := "1", "1"
	if nOK {
		nExit = "0"
	}
	if interactiveOK {
		iExit = "0"
	}
	script := "#!/bin/sh\n" +
		"echo \"$@\" >> \"" + logPath + "\"\n" +
		"if [ \"$1\" = \"-n\" ]; then\n" +
		"  if [ " + nExit + " -eq 0 ]; then exit 0; fi\n" +
		"  echo 'sudo: a password is required' 1>&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"exit " + iExit + "\n"
	sudoPath := filepath.Join(dir, "sudo")
	if err := os.WriteFile(sudoPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

// sudoInvocations returns the recorded stub-sudo calls, splitting each into its
// interactive vs non-interactive (`-n`) count.
func sudoInvocations(t *testing.T, logPath string) (nonInteractive, interactive int) {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0
		}
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "-n ") {
			nonInteractive++
		} else {
			interactive++
		}
	}
	return nonInteractive, interactive
}

func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatalf("run helper process: %v", err)
	}
	return cmd.Process.Pid
}

func writePIDFile(t *testing.T, pid int) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "test.pid")
	if err := os.WriteFile(f, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// ---------- isHelperProcess ----------

func TestIsHelperProcess_VmnetHelper(t *testing.T) {
	withLookupComm(t, func(int) (string, error) { return "/opt/homebrew/libexec/vmnet-helper", nil })
	if !isHelperProcess(1) {
		t.Error("should match a comm containing vmnet-helper")
	}
}

func TestIsHelperProcess_Sudo(t *testing.T) {
	// On macOS 15 the recorded PID is sudo's; both bare 'sudo' and '/usr/bin/sudo'
	// must be recognised so we still manage the child via its sudo parent — but
	// only when the sudo invocation actually targets vmnet-helper (argv gate).
	withLookupCmdline(t, func(int) (string, error) {
		return "sudo -n /opt/homebrew/libexec/vmnet-helper --socket …", nil
	})
	withLookupComm(t, func(int) (string, error) { return "sudo", nil })
	if !isHelperProcess(1) {
		t.Error("should match bare 'sudo' whose argv references vmnet-helper")
	}
	withLookupComm(t, func(int) (string, error) { return "/usr/bin/sudo", nil })
	if !isHelperProcess(1) {
		t.Error("should match '/usr/bin/sudo' whose argv references vmnet-helper")
	}
}

func TestIsHelperProcess_SudoReusedPID(t *testing.T) {
	// A recycled PID now belongs to an unrelated sudo (e.g. `sudo -i`). The comm
	// is "sudo" but its argv does not reference vmnet-helper, so we must NOT treat
	// it as ours — otherwise Stop/ForceStop would signal-kill an innocent process.
	withLookupComm(t, func(int) (string, error) { return "sudo", nil })
	withLookupCmdline(t, func(int) (string, error) { return "sudo -i", nil })
	if isHelperProcess(1) {
		t.Error("must not match a bare sudo whose argv does not reference vmnet-helper")
	}
}

func TestIsHelperProcess_SudoCmdlineLookupError(t *testing.T) {
	// If the comm says "sudo" but the argv lookup fails, we cannot confirm the
	// process is ours, so fail closed (do not signal it).
	withLookupComm(t, func(int) (string, error) { return "sudo", nil })
	withLookupCmdline(t, func(int) (string, error) { return "", os.ErrNotExist })
	if isHelperProcess(1) {
		t.Error("must be false when the sudo argv lookup fails")
	}
}

func TestIsHelperProcess_WrongProcess(t *testing.T) {
	withLookupComm(t, func(int) (string, error) { return "bash", nil })
	if isHelperProcess(os.Getpid()) {
		t.Error("must not match an unrelated process comm")
	}
}

func TestIsHelperProcess_LookupError(t *testing.T) {
	withLookupComm(t, func(int) (string, error) { return "", os.ErrNotExist })
	if isHelperProcess(999999) {
		t.Error("must be false when comm lookup fails")
	}
}

// ---------- Stop / ForceStop stale-PID handling ----------

func TestStop_StalePIDFileRemovedNotKilled(t *testing.T) {
	// PID file points at our own live PID but comm isn't a helper. Stop must
	// remove the stale file and NOT signal the wrong process.
	withLookupComm(t, func(int) (string, error) { return "not-a-helper", nil })
	f := writePIDFile(t, os.Getpid())

	if err := Stop(f); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Errorf("Stop should remove the stale PID file, stat err = %v", err)
	}
	// Still alive → the wrong process was not killed.
}

func TestForceStop_StalePIDFileRemovedNotKilled(t *testing.T) {
	withLookupComm(t, func(int) (string, error) { return "not-a-helper", nil })
	f := writePIDFile(t, os.Getpid())

	if err := ForceStop(f); err != nil {
		t.Fatalf("ForceStop() error: %v", err)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Errorf("ForceStop should remove the stale PID file, stat err = %v", err)
	}
}

func TestStop_MissingPIDFile(t *testing.T) {
	if err := Stop(filepath.Join(t.TempDir(), "nope.pid")); err == nil {
		t.Error("Stop should error on a missing PID file")
	}
}

// ---------- IsRunning / CleanupPIDFile ----------

func TestIsRunning_WrongProcess(t *testing.T) {
	withLookupComm(t, func(int) (string, error) { return "bash", nil })
	f := writePIDFile(t, os.Getpid())
	if IsRunning(f) {
		t.Error("IsRunning must be false when the live PID is not a helper")
	}
}

func TestCleanupPIDFile_RemovesStale(t *testing.T) {
	withLookupComm(t, func(int) (string, error) { return "", os.ErrNotExist })
	f := writePIDFile(t, deadPID(t))
	if err := CleanupPIDFile(f); err != nil {
		t.Fatalf("CleanupPIDFile() error: %v", err)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Errorf("CleanupPIDFile should remove a stale PID file, stat err = %v", err)
	}
}

func TestCleanupPIDFile_RefusesRunning(t *testing.T) {
	withLookupComm(t, func(int) (string, error) { return "vmnet-helper", nil })
	f := writePIDFile(t, os.Getpid())
	if err := CleanupPIDFile(f); err == nil {
		t.Error("CleanupPIDFile should refuse to remove a PID file for a running helper")
	}
}

// ---------- killChild ----------

func TestKillChild_NilSafe(t *testing.T) {
	// Must not panic on a nil cmd or a cmd with no Process.
	killChild(nil)
	killChild(&exec.Cmd{})
}

func TestKillChild_KillsLiveProcess(t *testing.T) {
	// macOS 26+ path: the helper runs as the invoking user, so killChild
	// SIGKILLs it directly AND reaps it (Wait after Kill), leaving no zombie;
	// we confirm the PID is gone via signal 0.
	forceMacOSVersion(t, "26.0")
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	pid := cmd.Process.Pid

	killChild(cmd)

	// After killChild the process is reaped; signal 0 must report it gone
	// (ESRCH). A live process would return nil.
	if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
		t.Errorf("after killChild, Kill(pid, 0) = %v, want ESRCH (process gone)", err)
	}
}

func TestKillChild_SudoPathSignalsViaHelperAndDoesNotBlock(t *testing.T) {
	// macOS ≤25 path: the recorded process is the root-owned `sudo` child.
	// A direct Kill would EPERM and Wait would block forever. killChild must
	// instead route through signalHelper (sudo -n kill) and return promptly
	// without Wait-ing on a process it cannot reap. We stub signalHelper so no
	// real signal is sent and assert both the routing and the non-blocking.
	forceMacOSVersion(t, "15.4")

	var gotPID int
	var gotSig string
	called := make(chan struct{}, 1)
	withSignalHelper(t, func(pid int, sig string) error {
		gotPID, gotSig = pid, sig
		called <- struct{}{}
		return nil
	})

	// A process we own that would outlive the test if killChild blocked or
	// failed to signal it. signalHelper is stubbed to a no-op, so killChild
	// won't actually stop it — we reap it ourselves at the end.
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		var ws syscall.WaitStatus
		_, _ = syscall.Wait4(pid, &ws, 0, nil)
	})

	done := make(chan struct{})
	go func() { killChild(cmd); close(done) }()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("killChild blocked on the sudo path (regression: it must not Wait on an unreapable root process)")
	}

	select {
	case <-called:
	default:
		t.Fatal("killChild did not route through signalHelper on the sudo path")
	}
	if gotPID != pid {
		t.Errorf("signalHelper pid = %d, want %d", gotPID, pid)
	}
	if gotSig != sigTERM {
		t.Errorf("signalHelper sig = %q, want %q (SIGTERM lets sudo forward to the helper)", gotSig, sigTERM)
	}
}

func TestStart_RemovesPIDFileAndKillsChildOnInitFailure(t *testing.T) {
	// H2 regression: the PID file is written right after the fork, before the
	// fallible JSON/bridge steps. If one of those fails, Start must both kill
	// the running child and remove the PID file, so no orphaned helper is left
	// behind with (or without) a stale PID file. macOS 26+ path so killChild
	// SIGKILLs directly.
	forceMacOSVersion(t, "26.0")

	// A fake vmnet-helper: record its own PID, emit a line that is NOT valid
	// start JSON (so parseStartJSON fails after the PID file is written), then
	// exec sleep so the surviving process keeps the same PID for the liveness
	// assertion below.
	sidePID := filepath.Join(t.TempDir(), "child.pid")
	script := "#!/bin/sh\necho $$ > " + sidePID + "\necho not-json\nexec sleep 300\n"
	bin := filepath.Join(t.TempDir(), "fake-vmnet-helper")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	pidFile := filepath.Join(t.TempDir(), "helper.pid")

	cfg := HelperConfig{
		Name:          "test",
		OperationMode: ModeHost,
		SocketPath:    filepath.Join(t.TempDir(), "vmnet.sock"),
		BinaryPath:    bin,
		PIDFile:       pidFile,
	}

	res, startErr := Start(cfg)
	if startErr == nil {
		t.Fatal("Start should error when the helper emits invalid start JSON")
	}
	if res != nil {
		t.Errorf("Start should return a nil result on failure, got %+v", res)
	}

	// The PID file must not survive a failed Start.
	if _, statErr := os.Stat(pidFile); !os.IsNotExist(statErr) {
		t.Errorf("PID file should be removed after a failed Start, stat err = %v", statErr)
	}

	// The child must have been killed (no leaked helper).
	childPID := readIntFile(t, sidePID)
	var ws syscall.WaitStatus
	_, _ = syscall.Wait4(childPID, &ws, 0, nil) // reap if it was ours
	if err := syscall.Kill(childPID, 0); err != syscall.ESRCH {
		t.Errorf("child helper should be dead after a failed Start, Kill(pid,0) = %v, want ESRCH", err)
	}
}

func readIntFile(t *testing.T, path string) int {
	t.Helper()
	// The fake helper writes its PID asynchronously; give it a brief moment.
	for range 50 {
		if b, err := os.ReadFile(path); err == nil {
			if n, perr := strconv.Atoi(strings.TrimSpace(string(b))); perr == nil {
				return n
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("child never recorded its PID at %s", path)
	return 0
}

// ---------- readLineWithDeadline ----------

func TestReadLineWithDeadline_Timeout(t *testing.T) {
	// A pipe that is never written to must cause the read to time out rather
	// than block forever (the guard against vmnet-helper hanging at startup).
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})

	start := time.Now()
	_, err = readLineWithDeadline(r, 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected a timeout error when nothing is written")
	}
	elapsed := time.Since(start)
	if elapsed < 150*time.Millisecond {
		t.Errorf("returned too early (%v); deadline not honored", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Errorf("returned too late (%v); should be near the 200ms deadline", elapsed)
	}
}

func TestReadLineWithDeadline_ReadsLine(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })

	go func() {
		_, _ = w.WriteString("hello world\nsecond line\n")
		_ = w.Close()
	}()

	line, err := readLineWithDeadline(r, 2*time.Second)
	if err != nil {
		t.Fatalf("readLineWithDeadline() error: %v", err)
	}
	if string(line) != "hello world" {
		t.Errorf("got %q, want first line only", string(line))
	}
}

func TestReadLineWithDeadline_EOFNoData(t *testing.T) {
	// Writer closes without writing → EOF before any line → error.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	_ = w.Close()

	if _, err := readLineWithDeadline(r, 2*time.Second); err == nil {
		t.Error("expected error when stdout closes before any line is emitted")
	}
}

// ---------- signalHelper (macOS ≤15 sudo path) ----------

const signalTestPID = 424242

// TestSignalHelper_NonInteractiveFastPath: `sudo -n kill` succeeds (NOPASSWD or a
// cached credential) → no interactive prompt regardless of the gate.
func TestSignalHelper_NonInteractiveFastPath(t *testing.T) {
	forceMacOSVersion(t, "15.4")
	withInteractiveSignaling(t, false)
	log := fakeSudo(t, true /*nOK*/, false)

	if err := signalHelper(signalTestPID, sigTERM); err != nil {
		t.Fatalf("signalHelper() error = %v, want nil", err)
	}
	n, i := sudoInvocations(t, log)
	if n != 1 || i != 0 {
		t.Errorf("sudo calls = (non-interactive %d, interactive %d), want (1, 0)", n, i)
	}
	if interactiveAttempted {
		t.Error("interactiveAttempted set on the non-interactive fast path")
	}
}

// TestSignalHelper_NonTTYReturnsActionableError: `sudo -n` refused and interactive
// signaling disabled (non-TTY) → actionable error, no prompt, no hang.
func TestSignalHelper_NonTTYReturnsActionableError(t *testing.T) {
	forceMacOSVersion(t, "15.4")
	withInteractiveSignaling(t, false)
	log := fakeSudo(t, false /*nOK*/, false)

	err := signalHelper(signalTestPID, sigTERM)
	if err == nil {
		t.Fatal("signalHelper() error = nil, want actionable error")
	}
	if !strings.Contains(err.Error(), "interactive terminal") {
		t.Errorf("error %q should point the operator at an interactive terminal", err)
	}
	if _, i := sudoInvocations(t, log); i != 0 {
		t.Errorf("interactive sudo invoked %d times on a non-TTY, want 0", i)
	}
}

// TestSignalHelper_InteractiveFallbackSucceeds: `sudo -n` refused but a terminal is
// attached → falls back to interactive `sudo kill`, which succeeds.
func TestSignalHelper_InteractiveFallbackSucceeds(t *testing.T) {
	forceMacOSVersion(t, "15.4")
	withInteractiveSignaling(t, true)
	log := fakeSudo(t, false /*nOK*/, true /*interactiveOK*/)

	if err := signalHelper(signalTestPID, sigTERM); err != nil {
		t.Fatalf("signalHelper() error = %v, want nil", err)
	}
	n, i := sudoInvocations(t, log)
	if n != 1 || i != 1 {
		t.Errorf("sudo calls = (non-interactive %d, interactive %d), want (1, 1)", n, i)
	}
	if !interactiveAttempted {
		t.Error("interactiveAttempted not set after an interactive prompt")
	}
}

// TestSignalHelper_DeclineDoesNotPromptTwice mirrors childproc.Supervisor.Stop's
// SIGTERM→SIGKILL escalation: a declined SIGTERM prompt must not put up a second
// prompt on the follow-up SIGKILL.
func TestSignalHelper_DeclineDoesNotPromptTwice(t *testing.T) {
	forceMacOSVersion(t, "15.4")
	withInteractiveSignaling(t, true)
	log := fakeSudo(t, false /*nOK*/, false /*interactive declined*/)

	if err := signalHelper(signalTestPID, sigTERM); err == nil {
		t.Fatal("first signalHelper() error = nil, want failure on a declined prompt")
	}
	if err := signalHelper(signalTestPID, sigKILL); err == nil {
		t.Fatal("second signalHelper() error = nil, want failure")
	}
	// Two `sudo -n` fast-path attempts (one per call); exactly one interactive
	// prompt total — the SIGKILL must not prompt again.
	n, i := sudoInvocations(t, log)
	if i != 1 {
		t.Errorf("interactive prompts = %d, want exactly 1 (no second prompt on SIGKILL)", i)
	}
	if n != 2 {
		t.Errorf("non-interactive attempts = %d, want 2", n)
	}
}
