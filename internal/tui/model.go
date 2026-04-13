package tui

import (
	"errors"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// StepStatus tracks the state of an individual step.
type StepStatus int

const (
	StepPending StepStatus = iota
	StepActive
	StepDone
	StepFailed
)

// Step holds the display info for one phase.
type Step struct {
	Name     string
	Status   StepStatus
	Detail   string  // short detail shown next to step name
	Indent   int     // 0 = top-level, 1 = sub-step (indented)
	Progress float64 // 0.0–1.0; rendered as bar when > 0 and StepActive
}

// DoneConfig controls what is shown when all work completes successfully.
type DoneConfig struct {
	SuccessMsg string   // e.g. `Instance "dev" is ready!`
	HintLines  []string // e.g. ["SSH: abox ssh dev"]
}

// PhaseStartMsg marks a phase as active.
type PhaseStartMsg struct{ Phase int }

// PhaseDoneMsg marks a phase as complete (or failed).
type PhaseDoneMsg struct {
	Phase int
	Err   error
}

// PhaseProgressMsg updates the progress bar for an active phase.
type PhaseProgressMsg struct {
	Phase   int
	Percent float64 // 0.0–1.0
	Detail  string  // e.g. "230 / 512 MB"
}

// ProgressMsg carries a line of output from the work goroutine.
type ProgressMsg struct {
	Line string
}

// WarnMsg carries a warning line from the work goroutine (stderr/slog).
type WarnMsg struct {
	Line string
}

// allDoneMsg signals that all work is complete.
type allDoneMsg struct{ err error }

// tickMsg drives the spinner animation.
type tickMsg struct{}

// StepModel is the bubbletea model for a step-checklist TUI.
type StepModel struct {
	label       string
	done        DoneConfig
	steps       []Step
	logLines    []string // ring buffer of output lines
	warnLines   []string // ring buffer of warning lines
	logExpanded bool     // toggle: compact (10 lines) vs expanded (40 lines)
	finished    bool
	err         error
	tick        int // spinner frame counter
	width       int // terminal width
}

const (
	maxLogLines      = 1000 // ring buffer capacity
	maxWarnLines     = 100  // ring buffer capacity for warnings
	compactLogLines  = 10
	expandedLogLines = 40
	spinnerInterval  = 100 // ms
)

// braille spinner frames
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Styles
var (
	headerStyle     = lipgloss.NewStyle().Bold(true)
	doneStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	failStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	activeStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
	pendingStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	dimStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	borderStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	warnBorderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
)

// NewStepModel creates a new StepModel.
func NewStepModel(label string, steps []Step, done DoneConfig) StepModel {
	return StepModel{
		label:    label,
		done:     done,
		steps:    steps,
		logLines: make([]string, 0, 128),
	}
}

// Err returns the error captured by the model (if any).
func (m StepModel) Err() error {
	return m.err
}

func (m StepModel) Init() tea.Cmd {
	return tickCmd()
}

func (m StepModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		return m.handleKeyMsg(msg)
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil
	case tickMsg:
		return m.handleTickMsg()
	case PhaseStartMsg:
		m.handlePhaseStartMsg(msg)
		return m, nil
	case PhaseDoneMsg:
		m.handlePhaseDoneMsg(msg)
		return m, nil
	case PhaseProgressMsg:
		m.handlePhaseProgressMsg(msg)
		return m, nil
	case ProgressMsg:
		m.appendLogLine(msg.Line)
		return m, nil
	case WarnMsg:
		m.appendWarnLine(msg.Line)
		return m, nil
	case allDoneMsg:
		m.finished = true
		m.err = msg.err
		return m, tea.Quit
	}
	return m, nil
}

func (m StepModel) handleKeyMsg(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		m.finished = true
		m.err = errors.New("interrupted")
		return m, tea.Quit
	case "v":
		m.logExpanded = !m.logExpanded
		return m, nil
	}
	return m, nil
}

func (m StepModel) handleTickMsg() (tea.Model, tea.Cmd) {
	if m.finished {
		return m, nil
	}
	m.tick++
	return m, tickCmd()
}

func (m *StepModel) handlePhaseStartMsg(msg PhaseStartMsg) {
	if msg.Phase >= 0 && msg.Phase < len(m.steps) {
		// Only activate if still pending (idempotent).
		if m.steps[msg.Phase].Status == StepPending {
			m.steps[msg.Phase].Status = StepActive
		}
	}
}

func (m *StepModel) handlePhaseDoneMsg(msg PhaseDoneMsg) {
	if msg.Phase >= 0 && msg.Phase < len(m.steps) {
		if msg.Err != nil {
			m.steps[msg.Phase].Status = StepFailed
			m.steps[msg.Phase].Detail = msg.Err.Error()
		} else {
			m.steps[msg.Phase].Status = StepDone
			m.steps[msg.Phase].Progress = 0 // clear bar on completion
		}
	}
}

func (m *StepModel) handlePhaseProgressMsg(msg PhaseProgressMsg) {
	if msg.Phase >= 0 && msg.Phase < len(m.steps) {
		m.steps[msg.Phase].Progress = msg.Percent
		m.steps[msg.Phase].Detail = msg.Detail
	}
}

// appendLogLine adds a line to the log ring buffer.
// The re-slice doesn't shrink the backing array, but with maxLogLines=1000
// and short-lived CLI sessions the memory overhead is negligible.
func (m *StepModel) appendLogLine(line string) {
	m.logLines = append(m.logLines, line)
	if len(m.logLines) > maxLogLines {
		excess := len(m.logLines) - maxLogLines
		m.logLines = m.logLines[excess:]
	}
}

func (m *StepModel) appendWarnLine(line string) {
	m.warnLines = append(m.warnLines, line)
	if len(m.warnLines) > maxWarnLines {
		excess := len(m.warnLines) - maxWarnLines
		m.warnLines = m.warnLines[excess:]
	}
}

func (m StepModel) View() tea.View {
	w := m.effectiveWidth()

	var sb strings.Builder
	sb.WriteString(headerStyle.Render(m.label))
	sb.WriteString("\n\n")

	m.renderSteps(&sb, w)
	m.renderLogPanel(&sb, w)
	m.renderWarnings(&sb, w)
	m.renderFinalMessage(&sb)

	return tea.NewView(sb.String())
}

// effectiveWidth returns the terminal width, defaulting to 80.
func (m StepModel) effectiveWidth() int {
	if m.width > 0 {
		return m.width
	}
	return 80
}

// renderSteps writes the step checklist section into sb.
func (m StepModel) renderSteps(sb *strings.Builder, w int) {
	for _, s := range m.steps {
		indent := strings.Repeat("  ", s.Indent+1)
		sb.WriteString(indent)
		sb.WriteString(m.stepIcon(s))
		sb.WriteString(" ")
		sb.WriteString(s.Name)

		showBar := s.Status == StepActive && s.Progress > 0
		if s.Detail != "" && !showBar {
			sb.WriteString(dimStyle.Render(fmt.Sprintf(" (%s)", s.Detail)))
		}
		sb.WriteString("\n")

		if showBar {
			sb.WriteString(renderProgressBar(w, s.Progress, s.Detail))
			sb.WriteString("\n")
		}
	}
}

// stepIcon returns the rendered icon string for a step's current status.
func (m StepModel) stepIcon(s Step) string {
	switch s.Status {
	case StepDone:
		return doneStyle.Render("✓")
	case StepFailed:
		return failStyle.Render("✗")
	case StepActive:
		frame := spinnerFrames[m.tick%len(spinnerFrames)]
		return activeStyle.Render(frame)
	case StepPending:
		return pendingStyle.Render("○")
	default:
		return pendingStyle.Render("○")
	}
}

// renderLogPanel writes the collapsible output log panel into sb.
func (m StepModel) renderLogPanel(sb *strings.Builder, w int) {
	if len(m.logLines) == 0 || (m.finished && m.err == nil) {
		return
	}

	lineWidth := max(w-4, 20)
	sb.WriteString("\n")
	sb.WriteString(m.logPanelHeader(lineWidth))
	sb.WriteString("\n")

	visibleLines := compactLogLines
	if m.logExpanded {
		visibleLines = expandedLogLines
	}

	tail := tailSlice(m.logLines, visibleLines)
	renderTruncatedLines(sb, tail, lineWidth, nil)

	sb.WriteString("  ")
	sb.WriteString(borderStyle.Render(strings.Repeat("─", lineWidth)))
	sb.WriteString("\n")
}

// logPanelHeader builds the decorated header line for the output panel.
func (m StepModel) logPanelHeader(lineWidth int) string {
	hint := "[v] expand"
	if m.logExpanded {
		hint = "[v] collapse"
	}
	label := " output "
	hintStr := " " + hint + " "
	dashCount := max(lineWidth-len(label)-len(hintStr), 2)
	leftDashes := 3
	rightDashes := max(dashCount-leftDashes, 1)

	return "  " + borderStyle.Render(strings.Repeat("─", leftDashes)+label) +
		borderStyle.Render(strings.Repeat("─", rightDashes)+hintStr)
}

// renderWarnings writes the warnings panel into sb.
func (m StepModel) renderWarnings(sb *strings.Builder, w int) {
	if len(m.warnLines) == 0 {
		return
	}

	lineWidth := max(w-4, 20)
	sb.WriteString("\n")

	warnLabel := " warnings "
	warnDashCount := max(lineWidth-len(warnLabel), 2)
	leftDashes := 3
	rightDashes := max(warnDashCount-leftDashes, 1)

	sb.WriteString("  ")
	sb.WriteString(warnBorderStyle.Render(strings.Repeat("─", leftDashes) + warnLabel))
	sb.WriteString(warnBorderStyle.Render(strings.Repeat("─", rightDashes)))
	sb.WriteString("\n")

	renderTruncatedLines(sb, m.warnLines, lineWidth, &warnBorderStyle)

	sb.WriteString("  ")
	sb.WriteString(warnBorderStyle.Render(strings.Repeat("─", lineWidth)))
	sb.WriteString("\n")
}

// renderFinalMessage writes the success or error message into sb.
func (m StepModel) renderFinalMessage(sb *strings.Builder) {
	if !m.finished {
		return
	}
	sb.WriteString("\n")
	if m.err == nil {
		sb.WriteString(doneStyle.Render(m.done.SuccessMsg))
		sb.WriteString("\n")
		for _, line := range m.done.HintLines {
			sb.WriteString(line)
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString(failStyle.Render(fmt.Sprintf("Error: %v", m.err)))
		sb.WriteString("\n")
	}
}

// tailSlice returns the last n elements of s, or all of s if len(s) <= n.
func tailSlice(s []string, n int) []string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// renderTruncatedLines writes lines to sb, truncating each to lineWidth.
// If style is non-nil it is applied to each line.
func renderTruncatedLines(sb *strings.Builder, lines []string, lineWidth int, style *lipgloss.Style) {
	for _, line := range lines {
		display := line
		if len(display) > lineWidth {
			display = display[:lineWidth-1] + "…"
		}
		sb.WriteString("  ")
		if style != nil {
			sb.WriteString(style.Render(display))
		} else {
			sb.WriteString(display)
		}
		sb.WriteString("\n")
	}
}

// renderProgressBar renders a lipgloss progress bar line.
func renderProgressBar(width int, pct float64, detail string) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 1 {
		pct = 1
	}

	// "    ████░░░░ 45.2%  230 / 512 MB"
	pctStr := fmt.Sprintf("%4.1f%%", pct*100)
	detailStr := ""
	if detail != "" {
		detailStr = "  " + detail
	}

	// Reserve space: 4 indent + 1 space + pctStr + detailStr + 2 margin
	reserved := 4 + 1 + len(pctStr) + len(detailStr) + 2
	barWidth := max(width-reserved, 10)

	filled := min(int(pct*float64(barWidth)), barWidth)
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	return fmt.Sprintf("    %s %s%s", activeStyle.Render(bar), pctStr, detailStr)
}

func tickCmd() tea.Cmd {
	return tea.Tick(
		time.Duration(spinnerInterval)*time.Millisecond,
		func(_ time.Time) tea.Msg {
			return tickMsg{}
		},
	)
}
