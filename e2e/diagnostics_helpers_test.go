//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests cover the pure diagnostics helpers (no VM/backend required), in
// particular the byte-clamping and control-byte stripping that guard the on-failure
// log dump against short files, oversized logs, and binary-ish console output.

func TestSanitizePrintable(t *testing.T) {
	in := "ok line\ttab\r\nnext\x00\x07\x1b[31mbad\x7f end\xc3\xa9"
	got := sanitizePrintable(in)

	// Kept: printable ASCII, tab, CR, LF, and a valid multibyte rune (é).
	for _, want := range []string{"ok line\ttab\r\nnext", "bad", " end", "é"} {
		if !strings.Contains(got, want) {
			t.Errorf("sanitizePrintable dropped %q; got %q", want, got)
		}
	}
	// Stripped: NUL, BEL, ESC, DEL.
	for _, bad := range []string{"\x00", "\x07", "\x1b", "\x7f"} {
		if strings.Contains(got, bad) {
			t.Errorf("sanitizePrintable kept control byte %q; got %q", bad, got)
		}
	}
}

func TestTailFile(t *testing.T) {
	dir := t.TempDir()

	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}

	// Empty file -> empty string, no error.
	if got, err := tailFile(write("empty.log", ""), 16); err != nil || got != "" {
		t.Errorf("tailFile(empty) = %q, %v; want \"\", nil", got, err)
	}

	// File smaller than the cap -> full (sanitized) content; a negative relative seek
	// must NOT be attempted here.
	if got, err := tailFile(write("small.log", "hello\n"), 1024); err != nil || got != "hello\n" {
		t.Errorf("tailFile(small) = %q, %v; want \"hello\\n\", nil", got, err)
	}

	// File larger than the cap -> only the trailing cap bytes.
	big := strings.Repeat("A", 100) + "TAILMARKER"
	got, err := tailFile(write("big.log", big), 10)
	if err != nil {
		t.Fatalf("tailFile(big): %v", err)
	}
	if got != "TAILMARKER" {
		t.Errorf("tailFile(big) = %q; want last 10 bytes %q", got, "TAILMARKER")
	}

	// Control bytes in content are stripped on the way out.
	if got, err := tailFile(write("ctl.log", "a\x00b\x07c\n"), 1024); err != nil || got != "abc\n" {
		t.Errorf("tailFile(ctl) = %q, %v; want \"abc\\n\", nil", got, err)
	}

	// Nonexistent file -> error.
	if _, err := tailFile(filepath.Join(dir, "nope.log"), 16); err == nil {
		t.Error("tailFile(nonexistent) = nil error; want error")
	}
}

// TestDiagnoseOnFailureLIFO documents the ordering contract the on-failure hook
// relies on: t.Cleanup runs last-added-first, so a diagnostics hook registered AFTER
// the instance-removal cleanup runs BEFORE it (while logs still exist). This uses a
// plain t.Run with its own cleanups so it needs no backend.
func TestDiagnoseOnFailureLIFO(t *testing.T) {
	var order []string
	t.Run("scope", func(t *testing.T) {
		t.Cleanup(func() { order = append(order, "remove") })   // registered first
		t.Cleanup(func() { order = append(order, "diagnose") }) // registered second
	})
	if len(order) != 2 || order[0] != "diagnose" || order[1] != "remove" {
		t.Fatalf("cleanup order = %v; want [diagnose remove] (LIFO)", order)
	}
}
