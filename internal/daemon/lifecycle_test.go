package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestStopDaemon_UntrustedRuntimeDirSkipsPrimary: when the private runtime dir
// failed verification (Paths.RuntimeDirErr), everything inside it is
// attacker-controllable — a planted PID file would steer the signal fallback at
// an arbitrary abox process. stopDaemon must not read, act on, or remove the
// primary files then; with no owned legacy files either, it does nothing.
func TestStopDaemon_UntrustedRuntimeDirSkipsPrimary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("legacy fallback paths assume POSIX temp-dir semantics")
	}
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(tmp, "no-such-dir"))

	squat := filepath.Join(tmp, "squat")
	if err := os.Mkdir(squat, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(squat, "abox-dev-dns.sock")
	pid := filepath.Join(squat, "abox-dev-dns.pid")
	for _, f := range []string{sock, pid} {
		if err := os.WriteFile(f, []byte("1"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// shutdown is nil: reaching the RPC leg on an untrusted path would panic,
	// which is exactly what this test guards against.
	stopDaemon("dnsfilter", sock, pid, errors.New("squatted"), nil)

	for _, f := range []string{sock, pid} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("untrusted primary file %s was touched: %v", f, err)
		}
	}
}

// TestResolveRuntimePair covers the legacy read-fallback for daemon runtime
// files: sockets/PID files moved from the shared temp dir into the per-uid
// private directory, and daemons started by an older abox must stay stoppable
// (vfkit's resolvePIDFile precedent). The pair resolves AS A UNIT: any primary
// member present pins BOTH to primary (a stale primary PID file must not pair
// with a live legacy socket); only a fully-absent primary falls back to the
// owned legacy members (absent ones come back ""); with nothing anywhere, the
// primary pair is returned for the caller's error paths.
func TestResolveRuntimePair(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("legacy fallback paths assume POSIX temp-dir semantics")
	}
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	// RuntimeDir must fail so LegacyRuntimePath resolves to the shared temp dir.
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(tmp, "no-such-dir"))

	private := filepath.Join(tmp, "abox-private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(private, "abox-dev-dns.sock")
	pid := filepath.Join(private, "abox-dev-dns.pid")
	legacySock := filepath.Join(tmp, "abox-dev-dns.sock")
	legacyPID := filepath.Join(tmp, "abox-dev-dns.pid")
	write := func(f string) {
		t.Helper()
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if s, p := resolveRuntimePair(sock, pid); s != sock || p != pid {
		t.Errorf("nothing anywhere: pair = (%q, %q), want primary pair", s, p)
	}

	write(legacySock)
	if s, p := resolveRuntimePair(sock, pid); s != legacySock || p != "" {
		t.Errorf("legacy socket only: pair = (%q, %q), want (%q, \"\")", s, p, legacySock)
	}

	write(legacyPID)
	if s, p := resolveRuntimePair(sock, pid); s != legacySock || p != legacyPID {
		t.Errorf("legacy pair: pair = (%q, %q), want legacy pair", s, p)
	}

	// A stale primary PID file pins the WHOLE pair to primary: the legacy
	// daemon's live socket must not be mixed in (and later deleted) while the
	// signal leg targets a dead primary PID.
	write(pid)
	if s, p := resolveRuntimePair(sock, pid); s != sock || p != pid {
		t.Errorf("primary pid present: pair = (%q, %q), want primary pair", s, p)
	}

	write(sock)
	if s, p := resolveRuntimePair(sock, pid); s != sock || p != pid {
		t.Errorf("both primaries present: pair = (%q, %q), want primary pair", s, p)
	}
}

// TestSameExe covers the platform-agnostic executable-identity helper used by the
// Linux isAboxProcess path (and, via sameExeDarwin, the darwin one): an exact
// match is ours, a kernel " (deleted)" suffix (in-place upgrade) is tolerated,
// and an unrelated path is not.
func TestSameExe(t *testing.T) {
	const self = "/home/user/.local/bin/abox"
	tests := []struct {
		name     string
		observed string
		want     bool
	}{
		{"exact match", self, true},
		{"deleted suffix tolerated", self + " (deleted)", true},
		{"different binary", "/usr/bin/other", false},
		{"empty", "", false},
		{"prefix but not equal", "/home/user/.local/bin/abo", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sameExe(tt.observed, self); got != tt.want {
				t.Errorf("sameExe(%q, %q) = %v, want %v", tt.observed, self, got, tt.want)
			}
		})
	}
}
