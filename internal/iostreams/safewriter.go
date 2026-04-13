package iostreams

import (
	"io"
	"sync"
)

// SafeWriter is a mutex-protected io.Writer whose underlying writer can be
// swapped at runtime via Swap. This is used by the slog stderr handler so
// that the TUI can redirect log output without reinitializing the logger.
type SafeWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// NewSafeWriter returns a SafeWriter that initially writes to w.
func NewSafeWriter(w io.Writer) *SafeWriter {
	return &SafeWriter{w: w}
}

// Write implements io.Writer.
func (s *SafeWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// Swap replaces the underlying writer and returns the previous one.
func (s *SafeWriter) Swap(w io.Writer) io.Writer {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.w
	s.w = w
	return old
}
