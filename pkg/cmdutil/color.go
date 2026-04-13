package cmdutil

import (
	"fmt"
	"os"
)

// ColorScheme provides methods for colorizing output strings.
// When disabled (non-TTY or NO_COLOR set), methods return the input unmodified.
type ColorScheme struct {
	enabled bool
}

// NewColorScheme creates a ColorScheme. Colors are enabled only when
// isTerminal is true and the NO_COLOR environment variable is not set.
func NewColorScheme(isTerminal bool) *ColorScheme {
	enabled := isTerminal && os.Getenv("NO_COLOR") == ""
	return &ColorScheme{enabled: enabled}
}

// Enabled reports whether color output is active.
func (cs *ColorScheme) Enabled() bool {
	return cs.enabled
}

func (cs *ColorScheme) colorize(code, s string) string {
	if !cs.enabled {
		return s
	}
	return fmt.Sprintf("\033[%sm%s\033[0m", code, s)
}

// Bold returns s wrapped in bold ANSI escapes.
func (cs *ColorScheme) Bold(s string) string { return cs.colorize("1", s) }

// Red returns s in red.
func (cs *ColorScheme) Red(s string) string { return cs.colorize("31", s) }

// Green returns s in green.
func (cs *ColorScheme) Green(s string) string { return cs.colorize("32", s) }

// Yellow returns s in yellow.
func (cs *ColorScheme) Yellow(s string) string { return cs.colorize("33", s) }

// Gray returns s in gray (bright black).
func (cs *ColorScheme) Gray(s string) string { return cs.colorize("90", s) }
