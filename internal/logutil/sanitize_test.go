package logutil

import (
	"bytes"
	"strings"
	"testing"
)

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain text unchanged", "hello world", "hello world"},
		{"tabs and newlines preserved", "a\tb\nc\r\n", "a\tb\nc\r\n"},
		{"ansi color escape stripped", "\x1b[31mred\x1b[0m", "[31mred[0m"},
		{"bell and backspace stripped", "a\x07b\x08c", "abc"},
		{"del stripped", "a\x7fb", "ab"},
		{"osc sequence esc stripped", "\x1b]0;title\x07", "]0;title"},
		{"utf8 multibyte preserved", "café — 日本語", "café — 日本語"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizeString(tt.in); got != tt.want {
				t.Errorf("SanitizeString(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSanitizingWriter(t *testing.T) {
	var buf bytes.Buffer
	w := NewSanitizingWriter(&buf)

	input := "line1\x1b[2Jline2\n\x07done\ttab"
	n, err := w.Write([]byte(input))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	// Write must report the full input length so io.Copy sees no short write.
	if n != len(input) {
		t.Errorf("Write returned n=%d, want %d (full input length)", n, len(input))
	}

	got := buf.String()
	if strings.ContainsRune(got, 0x1b) || strings.ContainsRune(got, 0x07) {
		t.Errorf("output still contains control bytes: %q", got)
	}
	if want := "line1[2Jline2\ndone\ttab"; got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestSanitizingWriter_MultibyteAcrossWrites(t *testing.T) {
	// A UTF-8 rune split across two Write calls must survive intact: sanitizing
	// operates byte-wise and only drops bytes < 0x20 / 0x7f, so continuation
	// bytes (>= 0x80) always pass through.
	var buf bytes.Buffer
	w := NewSanitizingWriter(&buf)

	full := []byte("日") // 3 bytes: e6 97 a5
	if _, err := w.Write(full[:1]); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if _, err := w.Write(full[1:]); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if got := buf.String(); got != "日" {
		t.Errorf("split multibyte rune corrupted: got %q", got)
	}
}
