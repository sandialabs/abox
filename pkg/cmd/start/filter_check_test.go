package start

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// stubProcessSeams replaces the process-running and identity seams for a test.
func stubProcessSeams(t *testing.T, running func(int) bool, ident func(int) (bool, error)) {
	t.Helper()
	prevRun, prevID := processRunningFn, isAboxProcessFn
	processRunningFn, isAboxProcessFn = running, ident
	t.Cleanup(func() { processRunningFn, isAboxProcessFn = prevRun, prevID })
}

func writePIDFile(t *testing.T, dir string, pid int) string {
	t.Helper()
	p := filepath.Join(dir, "daemon.pid")
	if err := os.WriteFile(p, []byte(strconv.Itoa(pid)), 0o600); err != nil {
		t.Fatalf("write pid file: %v", err)
	}
	return p
}

func TestDaemonStateOf(t *testing.T) {
	tests := []struct {
		name    string
		pidBody string // contents of pid file; "" means do not create the file
		running func(int) bool
		ident   func(int) (bool, error)
		want    daemonState
	}{
		{
			name:    "missing pid file is dead",
			pidBody: "",
			running: func(int) bool { return true },
			ident:   func(int) (bool, error) { return true, nil },
			want:    daemonDead,
		},
		{
			name:    "garbage pid is dead",
			pidBody: "not-a-number",
			running: func(int) bool { return true },
			ident:   func(int) (bool, error) { return true, nil },
			want:    daemonDead,
		},
		{
			name:    "process not running is dead",
			pidBody: "4242",
			running: func(int) bool { return false },
			ident:   func(int) (bool, error) { return true, nil },
			want:    daemonDead,
		},
		{
			name:    "running but confirmed not abox is dead",
			pidBody: "4242",
			running: func(int) bool { return true },
			ident:   func(int) (bool, error) { return false, nil },
			want:    daemonDead,
		},
		{
			name:    "running and confirmed abox is alive",
			pidBody: "4242",
			running: func(int) bool { return true },
			ident:   func(int) (bool, error) { return true, nil },
			want:    daemonAlive,
		},
		{
			name:    "running but identity unverifiable",
			pidBody: "4242",
			running: func(int) bool { return true },
			ident:   func(int) (bool, error) { return false, errors.New("ps failed") },
			want:    daemonUnverifiable,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			pidFile := filepath.Join(dir, "daemon.pid")
			if tc.pidBody != "" {
				if err := os.WriteFile(pidFile, []byte(tc.pidBody), 0o600); err != nil {
					t.Fatalf("write pid file: %v", err)
				}
			}
			stubProcessSeams(t, tc.running, tc.ident)
			if got := daemonStateOf(pidFile); got != tc.want {
				t.Fatalf("daemonStateOf = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCheckAlreadyRunning_UnverifiablePreservesFiles is the regression test for
// the core bug: when a live process holds the PID but its identity cannot be
// confirmed, checkAlreadyRunning must NOT delete the socket/PID files and must
// surface an error — never silently nuke a possibly-live daemon's state.
func TestCheckAlreadyRunning_UnverifiablePreservesFiles(t *testing.T) {
	dir := t.TempDir()
	pidFile := writePIDFile(t, dir, 4242)
	socketPath := filepath.Join(dir, "daemon.sock")
	if err := os.WriteFile(socketPath, nil, 0o600); err != nil {
		t.Fatalf("write socket: %v", err)
	}

	stubProcessSeams(t,
		func(int) bool { return true },
		func(int) (bool, error) { return false, errors.New("identity unverifiable") },
	)

	var buf bytes.Buffer
	running, err := checkAlreadyRunning(&buf, "dns", pidFile, socketPath)
	if err == nil {
		t.Fatalf("expected error for unverifiable live process, got nil")
	}
	if running {
		t.Fatalf("expected running=false on unverifiable")
	}
	// Critical: files must still exist — we must not have deleted them.
	if _, statErr := os.Stat(pidFile); statErr != nil {
		t.Fatalf("PID file was deleted on unverifiable identity: %v", statErr)
	}
	if _, statErr := os.Stat(socketPath); statErr != nil {
		t.Fatalf("socket file was deleted on unverifiable identity: %v", statErr)
	}
}

func TestCheckAlreadyRunning_DeadCleansUpStaleFiles(t *testing.T) {
	dir := t.TempDir()
	pidFile := writePIDFile(t, dir, 4242)
	socketPath := filepath.Join(dir, "daemon.sock")
	if err := os.WriteFile(socketPath, nil, 0o600); err != nil {
		t.Fatalf("write socket: %v", err)
	}

	// Confirmed not-abox (PID reuse) => safe to clean up.
	stubProcessSeams(t,
		func(int) bool { return true },
		func(int) (bool, error) { return false, nil },
	)

	var buf bytes.Buffer
	running, err := checkAlreadyRunning(&buf, "dns", pidFile, socketPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if running {
		t.Fatalf("expected running=false")
	}
	if _, statErr := os.Stat(pidFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected stale PID file removed, stat err=%v", statErr)
	}
	if _, statErr := os.Stat(socketPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected stale socket removed, stat err=%v", statErr)
	}
}

func TestCheckAlreadyRunning_AliveReportsTrue(t *testing.T) {
	dir := t.TempDir()
	pidFile := writePIDFile(t, dir, 4242)
	socketPath := filepath.Join(dir, "daemon.sock")

	stubProcessSeams(t,
		func(int) bool { return true },
		func(int) (bool, error) { return true, nil },
	)

	running, err := checkAlreadyRunning(nil, "dns", pidFile, socketPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !running {
		t.Fatalf("expected running=true for a confirmed-alive abox daemon")
	}
}
