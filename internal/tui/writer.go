package tui

import (
	"bytes"
	"sync"

	tea "charm.land/bubbletea/v2"
)

// ProgressWriter implements io.Writer and sends each complete line as a
// tea.Msg to the bubbletea program. Partial lines are buffered until a
// newline is received.
type ProgressWriter struct {
	mu      sync.Mutex
	program *tea.Program
	buf     []byte
}

// NewProgressWriter creates a ProgressWriter that sends lines to p.
func NewProgressWriter(p *tea.Program) *ProgressWriter {
	return &ProgressWriter{
		program: p,
	}
}

// Write implements io.Writer. It buffers input and sends each complete line
// as a ProgressMsg to the bubbletea program.
func (w *ProgressWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	n := len(p)
	w.buf = append(w.buf, p...)

	for {
		idx := bytes.IndexByte(w.buf, '\n')
		if idx < 0 {
			break
		}
		line := string(w.buf[:idx])
		w.buf = w.buf[idx+1:]

		if line != "" {
			w.program.Send(ProgressMsg{Line: line})
		}
	}

	return n, nil
}

// Flush sends any remaining partial line in the buffer.
func (w *ProgressWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(w.buf) > 0 {
		line := string(w.buf)
		w.buf = nil
		w.program.Send(ProgressMsg{Line: line})
	}
}

// WarnWriter implements io.Writer and sends each complete line as a
// WarnMsg to the bubbletea program. Partial lines are buffered until a
// newline is received.
type WarnWriter struct {
	mu      sync.Mutex
	program *tea.Program
	buf     []byte
}

// NewWarnWriter creates a WarnWriter that sends lines to p.
func NewWarnWriter(p *tea.Program) *WarnWriter {
	return &WarnWriter{
		program: p,
	}
}

// Write implements io.Writer. It buffers input and sends each complete line
// as a WarnMsg to the bubbletea program.
func (w *WarnWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	n := len(p)
	w.buf = append(w.buf, p...)

	for {
		idx := bytes.IndexByte(w.buf, '\n')
		if idx < 0 {
			break
		}
		line := string(w.buf[:idx])
		w.buf = w.buf[idx+1:]

		if line != "" {
			w.program.Send(WarnMsg{Line: line})
		}
	}

	return n, nil
}

// Flush sends any remaining partial line in the buffer.
func (w *WarnWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(w.buf) > 0 {
		line := string(w.buf)
		w.buf = nil
		w.program.Send(WarnMsg{Line: line})
	}
}
