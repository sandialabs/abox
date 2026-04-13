// Package tui provides a shared bubbletea step-checklist model for CLI commands.
package tui

import (
	tea "charm.land/bubbletea/v2"
)

// PhaseNotifier allows business logic to signal step transitions.
// Two implementations exist: NoopNotifier (plain-text path) and
// TUINotifier (bubbletea path).
type PhaseNotifier interface {
	PhaseStart(idx int)
	PhaseDone(idx int, err error)
	PhaseProgress(idx int, pct float64, detail string)
	SubPhaseStart(parentIdx, subIdx int)
	SubPhaseDone(parentIdx, subIdx int, err error)
}

// NoopNotifier does nothing. Used for the plain-text code path where
// output already goes to an io.Writer.
type NoopNotifier struct{}

func (NoopNotifier) PhaseStart(int)                     {}
func (NoopNotifier) PhaseDone(int, error)               {}
func (NoopNotifier) PhaseProgress(int, float64, string) {}
func (NoopNotifier) SubPhaseStart(int, int)             {}
func (NoopNotifier) SubPhaseDone(int, int, error)       {}

// TUINotifier sends tea.Msg values to a running bubbletea program.
type TUINotifier struct {
	Program *tea.Program
}

func (n *TUINotifier) PhaseStart(idx int) {
	n.Program.Send(PhaseStartMsg{Phase: idx})
}

func (n *TUINotifier) PhaseDone(idx int, err error) {
	n.Program.Send(PhaseDoneMsg{Phase: idx, Err: err})
}

func (n *TUINotifier) PhaseProgress(idx int, pct float64, detail string) {
	n.Program.Send(PhaseProgressMsg{Phase: idx, Percent: pct, Detail: detail})
}

func (n *TUINotifier) SubPhaseStart(parentIdx, subIdx int) {
	// Activate parent (idempotent in the model — active stays active).
	n.Program.Send(PhaseStartMsg{Phase: parentIdx})
	// Activate sub-step.
	n.Program.Send(PhaseStartMsg{Phase: subIdx})
}

func (n *TUINotifier) SubPhaseDone(parentIdx, subIdx int, err error) {
	// parentIdx is not marked done here — the caller completes the parent
	// via PhaseDone after all sub-steps finish (see up.go doProvision).
	n.Program.Send(PhaseDoneMsg{Phase: subIdx, Err: err})
}
