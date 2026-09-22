//go:build darwin

package checkdeps

import (
	"os"
	"path/filepath"
	"testing"
)

// TestToolFoundResolvesOffPathVmnetHelper is the regression guard for the quiet
// startup check reporting a correctly-installed macOS vmnet-helper as missing.
// vmnet-helper installs off PATH (a Homebrew libexec dir), so the generic
// checkExecutable would not find it — but toolFound must, via platformResolveTool
// -> resolveVmnetHelper -> vmnethelper.ResolveBinaryPath (which honors the
// ABOX_VMNET_HELPER_PATH override).
func TestToolFoundResolvesOffPathVmnetHelper(t *testing.T) {
	off := filepath.Join(t.TempDir(), "vmnet-helper")
	if err := os.WriteFile(off, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ABOX_VMNET_HELPER_PATH", off)

	// The generic PATH check must NOT find it (it lives off PATH) — this is the
	// exact divergence the fix closes.
	if checkExecutable(depVmnetHelper) == nil {
		t.Fatalf("precondition failed: %q unexpectedly on PATH", off)
	}
	// toolFound consults the platform resolver, so it must report it found.
	if !toolFound(depVmnetHelper) {
		t.Errorf("toolFound(%q) = false; want true (resolved via ABOX_VMNET_HELPER_PATH)", depVmnetHelper)
	}
}

// TestToolFoundReportsMissingVmnetHelper asserts the "handled but not installed"
// contract: resolveVmnetHelper returns ok=true with an empty path when the
// binary is absent, and toolFound must treat that empty path as NOT found (never
// as a false positive).
func TestToolFoundReportsMissingVmnetHelper(t *testing.T) {
	t.Setenv("ABOX_VMNET_HELPER_PATH", filepath.Join(t.TempDir(), "does-not-exist"))
	if toolFound(depVmnetHelper) {
		t.Errorf("toolFound(%q) = true; want false (binary absent)", depVmnetHelper)
	}
}

func TestParseVfkitVersion(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want [3]int
		ok   bool
	}{
		{"homebrew line", "vfkit version: v0.6.4", [3]int{0, 6, 4}, true},
		{"no v prefix", "vfkit version 1.2.3", [3]int{1, 2, 3}, true},
		{"major.minor only", "vfkit v0.6", [3]int{0, 6, 0}, true},
		{"no version", "vfkit (unknown)", [3]int{0, 0, 0}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseVfkitVersion(tt.in)
			if ok != tt.ok || got != tt.want {
				t.Errorf("parseVfkitVersion(%q) = %v,%v; want %v,%v", tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestVersionLess(t *testing.T) {
	tests := []struct {
		a, b [3]int
		want bool
	}{
		{[3]int{0, 5, 9}, [3]int{0, 6, 0}, true},
		{[3]int{0, 6, 0}, [3]int{0, 6, 0}, false}, // equal is not less
		{[3]int{0, 6, 4}, [3]int{0, 6, 0}, false},
		{[3]int{1, 0, 0}, [3]int{0, 6, 0}, false},
		{[3]int{0, 6, 0}, [3]int{0, 6, 1}, true},
	}
	for _, tt := range tests {
		if got := versionLess(tt.a, tt.b); got != tt.want {
			t.Errorf("versionLess(%v, %v) = %v; want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
