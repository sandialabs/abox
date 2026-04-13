package tui

import (
	"fmt"
	"io"

	tea "charm.land/bubbletea/v2"
)

// WorkFunc is the signature for the background work function.
// It receives an io.Writer for normal output, an io.Writer for warnings/stderr,
// and a PhaseNotifier for step transitions.
type WorkFunc func(out io.Writer, errOut io.Writer, notify PhaseNotifier) error

// Run executes a bubbletea step-checklist TUI. It creates the program,
// spawns workFn in a goroutine, and blocks until the TUI exits.
func Run(label string, steps []Step, done DoneConfig, workFn WorkFunc) error {
	model := NewStepModel(label, steps, done)
	p := tea.NewProgram(model, tea.WithoutCatchPanics())

	writer := NewProgressWriter(p)
	warnWriter := NewWarnWriter(p)
	notify := &TUINotifier{Program: p}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				writer.Flush()
				warnWriter.Flush()
				p.Send(allDoneMsg{err: fmt.Errorf("panic: %v", r)})
			}
		}()
		workErr := workFn(writer, warnWriter, notify)
		writer.Flush()
		warnWriter.Flush()
		p.Send(allDoneMsg{err: workErr})
	}()

	finalModel, err := p.Run()
	if err != nil {
		return err
	}

	if m, ok := finalModel.(StepModel); ok && m.Err() != nil {
		return m.Err()
	}

	return nil
}
