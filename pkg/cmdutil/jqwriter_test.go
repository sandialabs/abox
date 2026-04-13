package cmdutil

import (
	"bytes"
	"strings"
	"testing"
)

func TestJQWriter_FieldExtraction(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewJQWriter(&buf, ".domain")
	if err != nil {
		t.Fatal(err)
	}
	input := `{"domain":"example.com","action":"allow"}` + "\n"
	if _, err := w.Write([]byte(input)); err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(buf.String())
	if got != "example.com" {
		t.Errorf("got %q, want %q", got, "example.com")
	}
}

func TestJQWriter_Select(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewJQWriter(&buf, `select(.action == "block")`)
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{
		`{"domain":"a.com","action":"allow"}`,
		`{"domain":"b.com","action":"block"}`,
		`{"domain":"c.com","action":"allow"}`,
	}
	for _, line := range lines {
		if _, err := w.Write([]byte(line + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	got := strings.TrimSpace(buf.String())
	if !strings.Contains(got, "b.com") {
		t.Errorf("expected blocked domain in output, got %q", got)
	}
	if strings.Contains(got, "a.com") || strings.Contains(got, "c.com") {
		t.Errorf("expected only blocked domain, got %q", got)
	}
}

func TestJQWriter_NonJSONPassthrough(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewJQWriter(&buf, ".domain")
	if err != nil {
		t.Fatal(err)
	}
	input := "Following DNS logs...\n"
	if _, err := w.Write([]byte(input)); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != input {
		t.Errorf("got %q, want %q", got, input)
	}
}

func TestJQWriter_MultipleResults(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewJQWriter(&buf, ".tags[]")
	if err != nil {
		t.Fatal(err)
	}
	input := `{"tags":["a","b","c"]}` + "\n"
	if _, err := w.Write([]byte(input)); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Errorf("got %d lines, want 3: %v", len(lines), lines)
	}
}

func TestJQWriter_InvalidExpression(t *testing.T) {
	_, err := NewJQWriter(nil, "invalid[[[")
	if err == nil {
		t.Fatal("expected error for invalid expression")
	}
}

func TestJQWriter_Flush(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewJQWriter(&buf, ".x")
	if err != nil {
		t.Fatal(err)
	}
	// Write without trailing newline.
	if _, err := w.Write([]byte(`{"x":42}`)); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatal("expected no output before Flush")
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(buf.String())
	if got != "42" {
		t.Errorf("got %q, want %q", got, "42")
	}
}
