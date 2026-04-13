package logutil

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTailBuffer(t *testing.T) {
	tests := []struct {
		name  string
		n     int
		input []string // separate writes
		want  string
	}{
		{
			name:  "fewer lines than capacity",
			n:     5,
			input: []string{"line1\nline2\n"},
			want:  "line1\nline2\n",
		},
		{
			name:  "exact capacity",
			n:     3,
			input: []string{"a\nb\nc\n"},
			want:  "a\nb\nc\n",
		},
		{
			name:  "overflow keeps last n",
			n:     2,
			input: []string{"a\nb\nc\nd\ne\n"},
			want:  "d\ne\n",
		},
		{
			name:  "multiple writes",
			n:     3,
			input: []string{"a\nb\n", "c\nd\n", "e\n"},
			want:  "c\nd\ne\n",
		},
		{
			name:  "partial line preserved",
			n:     5,
			input: []string{"a\npartial"},
			want:  "a\npartial",
		},
		{
			name:  "no input",
			n:     5,
			input: []string{},
			want:  "",
		},
		{
			name:  "single line no newline",
			n:     5,
			input: []string{"hello"},
			want:  "hello",
		},
		{
			name:  "overflow with partial line",
			n:     2,
			input: []string{"a\nb\nc\npartial"},
			want:  "b\nc\npartial",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			tb := NewTailBuffer(&out, tt.n)

			for _, s := range tt.input {
				if _, err := tb.Write([]byte(s)); err != nil {
					t.Fatalf("Write: %v", err)
				}
			}

			if err := tb.Flush(); err != nil {
				t.Fatalf("Flush: %v", err)
			}

			if got := out.String(); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadAll(t *testing.T) {
	t.Run("reads entire file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "test.log")
		content := "line1\nline2\nline3\n"
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}

		var out bytes.Buffer
		if err := ReadAll(&out, path, "no file"); err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		if got := out.String(); got != content {
			t.Errorf("got %q, want %q", got, content)
		}
	})

	t.Run("missing file prints message", func(t *testing.T) {
		var out bytes.Buffer
		if err := ReadAll(&out, "/nonexistent/path/file.log", "no file found"); err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		if got := strings.TrimSpace(out.String()); got != "no file found" {
			t.Errorf("got %q, want %q", got, "no file found")
		}
	})
}

func TestTailBufferWithJQPipeline(t *testing.T) {
	// Simulates the real pipeline: jq-filtered lines → TailBuffer → output.
	// Write many lines, only some of which would "match" the filter.
	var out bytes.Buffer
	tb := NewTailBuffer(&out, 3)

	// Simulate 10 filtered lines arriving
	for i := range 10 {
		line := []byte("matched-" + string(rune('0'+i)) + "\n")
		if _, err := tb.Write(line); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	if err := tb.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3: %v", len(lines), lines)
	}
	// Should be the last 3
	if lines[0] != "matched-7" || lines[1] != "matched-8" || lines[2] != "matched-9" {
		t.Errorf("got %v, want [matched-7 matched-8 matched-9]", lines)
	}
}
