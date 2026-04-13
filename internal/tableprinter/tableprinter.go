// Package tableprinter provides a table writer that adapts to terminal vs pipe output.
// In TTY mode, headers are bold and columns are aligned with tabwriter.
// In non-TTY mode, columns are tab-separated with no color for easy parsing.
package tableprinter

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/sandialabs/abox/pkg/cmdutil"
)

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// Table writes rows to a writer with optional colored headers.
type Table struct {
	out     io.Writer
	cs      *cmdutil.ColorScheme
	isTTY   bool
	headers []string
	rows    [][]string
}

// New creates a Table that writes to w. When isTTY is true, headers are
// bold and columns are auto-aligned; otherwise output is tab-separated.
func New(w io.Writer, cs *cmdutil.ColorScheme, isTTY bool) *Table {
	return &Table{out: w, cs: cs, isTTY: isTTY}
}

// AddHeader sets the column headers.
func (t *Table) AddHeader(headers ...string) {
	t.headers = headers
}

// AddRow appends a data row. Values are converted to strings via fmt.Sprint.
func (t *Table) AddRow(values ...any) {
	row := make([]string, len(values))
	for i, v := range values {
		row[i] = fmt.Sprint(v)
	}
	t.rows = append(t.rows, row)
}

// Render writes the table to the output writer.
func (t *Table) Render() {
	if t.isTTY {
		t.renderTTY()
	} else {
		t.renderPlain()
	}
}

// visibleWidth returns the display width of s after stripping ANSI escape sequences.
func visibleWidth(s string) int {
	return len(ansiRe.ReplaceAllString(s, ""))
}

func (t *Table) renderTTY() {
	allRows := t.buildPrintableRows()
	if len(allRows) == 0 {
		return
	}

	colWidths := computeColumnWidths(allRows)

	for _, row := range allRows {
		fmt.Fprintln(t.out, formatRow(row, colWidths))
	}
}

// buildPrintableRows assembles all rows for TTY rendering: bold headers followed by data rows.
func (t *Table) buildPrintableRows() [][]string {
	var allRows [][]string
	if len(t.headers) > 0 {
		colored := make([]string, len(t.headers))
		for i, h := range t.headers {
			colored[i] = t.cs.Bold(h)
		}
		allRows = append(allRows, colored)
	}
	allRows = append(allRows, t.rows...)
	return allRows
}

// computeColumnWidths returns the maximum visible width per column across all rows.
func computeColumnWidths(rows [][]string) []int {
	numCols := 0
	for _, row := range rows {
		if len(row) > numCols {
			numCols = len(row)
		}
	}
	widths := make([]int, numCols)
	for _, row := range rows {
		for i, cell := range row {
			if w := visibleWidth(cell); w > widths[i] {
				widths[i] = w
			}
		}
	}
	return widths
}

// formatRow renders a single row with padding aligned to the given column widths.
func formatRow(row []string, colWidths []int) string {
	var sb strings.Builder
	for i, cell := range row {
		sb.WriteString(cell)
		if i < len(row)-1 {
			pad := colWidths[i] - visibleWidth(cell) + 2
			for range pad {
				sb.WriteByte(' ')
			}
		}
	}
	return sb.String()
}

func (t *Table) renderPlain() {
	if len(t.headers) > 0 {
		fmt.Fprintln(t.out, strings.Join(t.headers, "\t"))
	}
	for _, row := range t.rows {
		fmt.Fprintln(t.out, strings.Join(row, "\t"))
	}
}
