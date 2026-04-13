package tableprinter

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sandialabs/abox/pkg/cmdutil"
)

func TestRenderTTY(t *testing.T) {
	var buf bytes.Buffer
	cs := cmdutil.NewColorScheme(true)
	tp := New(&buf, cs, true)
	tp.AddHeader("NAME", "STATE")
	tp.AddRow("dev", "running")
	tp.AddRow("prod", "stopped")
	tp.Render()

	out := buf.String()
	// Headers should be bold (contain ANSI escape)
	if !strings.Contains(out, "\033[") {
		t.Error("expected ANSI escapes in TTY mode")
	}
	if !strings.Contains(out, "dev") || !strings.Contains(out, "running") {
		t.Error("expected row data in output")
	}
	if !strings.Contains(out, "prod") || !strings.Contains(out, "stopped") {
		t.Error("expected second row in output")
	}
}

func TestRenderPlain(t *testing.T) {
	var buf bytes.Buffer
	cs := cmdutil.NewColorScheme(false)
	tp := New(&buf, cs, false)
	tp.AddHeader("NAME", "STATE")
	tp.AddRow("dev", "running")
	tp.AddRow("prod", "stopped")
	tp.Render()

	out := buf.String()
	// No ANSI escapes in plain mode
	if strings.Contains(out, "\033[") {
		t.Error("unexpected ANSI escapes in plain mode")
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %q", len(lines), out)
	}

	// Columns should be tab-separated
	if lines[0] != "NAME\tSTATE" {
		t.Errorf("header line = %q, want %q", lines[0], "NAME\tSTATE")
	}
	if lines[1] != "dev\trunning" {
		t.Errorf("row 1 = %q, want %q", lines[1], "dev\trunning")
	}
}

func TestRenderTTYAlignmentWithANSI(t *testing.T) {
	var buf bytes.Buffer
	cs := cmdutil.NewColorScheme(true)
	tp := New(&buf, cs, true)
	tp.AddHeader("NAME", "STATE", "IP")
	// Add rows with ANSI-colored STATE values of different visible lengths.
	tp.AddRow("claude", cs.Green("running"), "10.10.10.10")
	tp.AddRow("dev", cs.Red("stopped"), "10.10.20.10")
	tp.Render()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}

	// Strip ANSI from all lines and verify columns align at the same positions.
	stripped := make([]string, len(lines))
	for i, line := range lines {
		stripped[i] = ansiRe.ReplaceAllString(line, "")
	}

	// Find the column start positions in each stripped line.
	// "IP" column should start at the same position in all rows.
	for i := 1; i < len(stripped); i++ {
		headerIPIdx := strings.Index(stripped[0], "IP")
		rowIPIdx := strings.Index(stripped[i], "10.10.")
		if headerIPIdx != rowIPIdx {
			t.Errorf("line %d: IP column at %d, header IP at %d\nheader: %q\nrow:    %q",
				i, rowIPIdx, headerIPIdx, stripped[0], stripped[i])
		}
	}

	// Also verify both data rows have STATE column aligned.
	idx1 := strings.Index(stripped[1], "running")
	idx2 := strings.Index(stripped[2], "stopped")
	if idx1 != idx2 {
		t.Errorf("STATE column misaligned: row1=%d row2=%d", idx1, idx2)
	}
}

func TestNoHeaders(t *testing.T) {
	var buf bytes.Buffer
	cs := cmdutil.NewColorScheme(false)
	tp := New(&buf, cs, false)
	tp.AddRow("a", "b")
	tp.Render()

	out := strings.TrimSpace(buf.String())
	if out != "a\tb" {
		t.Errorf("got %q, want %q", out, "a\tb")
	}
}
