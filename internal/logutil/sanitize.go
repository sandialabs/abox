package logutil

import "io"

// sanitizeByte reports whether b is a control byte that must be dropped before
// rendering guest-influenced log content to a terminal. It drops the C0 control
// range and DEL — which includes ESC (0x1b), so ANSI/OSC escape sequences are
// neutralized — while preserving tab, newline, and carriage return so ordinary
// log formatting survives. Bytes >= 0x80 (UTF-8 continuation/lead bytes) pass
// through untouched, so multibyte runes are never corrupted.
func sanitizeByte(b byte) bool {
	switch b {
	case '\t', '\n', '\r':
		return false
	default:
		return b < 0x20 || b == 0x7f
	}
}

// SanitizeString drops terminal control bytes (see sanitizeByte) from s. Use it
// for one-shot strings; for streaming output use SanitizingWriter.
func SanitizeString(s string) string {
	out := make([]byte, 0, len(s))
	for i := range len(s) {
		if !sanitizeByte(s[i]) {
			out = append(out, s[i])
		}
	}
	return string(out)
}

// SanitizingWriter wraps an io.Writer, stripping terminal control bytes from
// everything written through it. It exists to defend the operator's terminal
// from guest-influenced log content (Tetragon event fields, DNS query names,
// HTTP URLs) that could embed ANSI/OSC escape sequences to spoof output, hide
// activity, or exploit terminal emulator bugs. Only the rendered stream is
// sanitized; the on-disk log files remain byte-for-byte faithful for forensics
// and machine parsing.
type SanitizingWriter struct {
	w io.Writer
}

// NewSanitizingWriter returns a SanitizingWriter wrapping w.
func NewSanitizingWriter(w io.Writer) *SanitizingWriter {
	return &SanitizingWriter{w: w}
}

// Write strips control bytes from p and writes the remainder to the underlying
// writer. It always reports len(p) written (with a nil error on success) so
// callers that check n == len(p) — e.g. io.Copy — do not see a short write when
// bytes are legitimately dropped.
func (s *SanitizingWriter) Write(p []byte) (int, error) {
	clean := make([]byte, 0, len(p))
	for _, b := range p {
		if !sanitizeByte(b) {
			clean = append(clean, b)
		}
	}
	if len(clean) > 0 {
		if _, err := s.w.Write(clean); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}
