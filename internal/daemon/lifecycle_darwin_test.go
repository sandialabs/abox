//go:build darwin

package daemon

import (
	"errors"
	"os"
	"testing"
)

// withProcComm swaps the procComm seam for the duration of a test.
func withProcComm(t *testing.T, fn func(pid int) (string, error)) {
	t.Helper()
	prev := procComm
	procComm = fn
	t.Cleanup(func() { procComm = prev })
}

func TestIsAboxProcess_SelfIsConfirmed(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	// Simulate ps returning our own executable path for the queried pid.
	withProcComm(t, func(int) (string, error) { return self, nil })

	ok, err := IsAboxProcess(os.Getpid())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected self to be confirmed abox process")
	}
}

func TestIsAboxProcess_OtherBinaryIsConfirmedNotAbox(t *testing.T) {
	// launchd / init style path: a real, running, but different executable.
	withProcComm(t, func(int) (string, error) { return "/sbin/launchd", nil })

	ok, err := IsAboxProcess(1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("expected /sbin/launchd to be confirmed NOT abox")
	}
}

func TestIsAboxProcess_LookupErrorIsUnverifiable(t *testing.T) {
	// ps failing (e.g. dead pid) must surface as an error, never as a confirmed
	// mismatch — callers rely on (false, err) to mean "do not act".
	wantErr := errors.New("ps -p 999999: exit status 1")
	withProcComm(t, func(int) (string, error) { return "", wantErr })

	ok, err := IsAboxProcess(999999)
	if err == nil {
		t.Fatalf("expected error for unverifiable pid, got nil")
	}
	if ok {
		t.Fatalf("expected ok=false on lookup error")
	}
}

func TestSameExeDarwin(t *testing.T) {
	self := "/Users/me/.local/bin/abox"
	tests := []struct {
		name     string
		observed string
		want     bool
	}{
		{"exact match", "/Users/me/.local/bin/abox", true},
		{"deleted suffix tolerated", "/Users/me/.local/bin/abox (deleted)", true},
		{"truncated prefix same basename stem", "/Users/me/.local/bin/ab", true},
		{"unrelated path", "/usr/bin/curl", false},
		{"prefix but different basename", "/Users/me/.local/bin/aboxd-helper", false},
		{"empty", "", false},
		{"prefix of a dir component only", "/Users/me/.local", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameExeDarwin(tc.observed, self); got != tc.want {
				t.Fatalf("sameExeDarwin(%q, %q) = %v, want %v", tc.observed, self, got, tc.want)
			}
		})
	}
}
