package cmdutil

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/spf13/cobra"
)

func TestAddJSONFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	e := AddJSONFlags(cmd)

	if e.Enabled() {
		t.Error("expected JSON to be disabled by default")
	}

	// Simulate setting the flag
	cmd.SetArgs([]string{"--json"})
	if err := cmd.ParseFlags([]string{"--json"}); err != nil {
		t.Fatal(err)
	}

	if !e.Enabled() {
		t.Error("expected JSON to be enabled after --json flag")
	}
}

func TestAddJSONFlags_JQImpliesJSON(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	e := AddJSONFlags(cmd)

	if err := cmd.ParseFlags([]string{"--jq", ".name"}); err != nil {
		t.Fatal(err)
	}

	if !e.Enabled() {
		t.Error("expected Enabled() to be true when --jq is set")
	}
}

func TestExporterWrite(t *testing.T) {
	e := &Exporter{enabled: true}
	var buf bytes.Buffer

	type item struct {
		Name string `json:"name"`
	}
	data := []item{{Name: "foo"}, {Name: "bar"}}

	if err := e.Write(&buf, data); err != nil {
		t.Fatal(err)
	}

	var got []item
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON output: %v\nraw: %s", err, buf.String())
	}

	if len(got) != 2 || got[0].Name != "foo" || got[1].Name != "bar" {
		t.Errorf("unexpected output: %+v", got)
	}
}

func TestExporterWrite_WithJQ(t *testing.T) {
	e := &Exporter{jq: ".[0].name"}
	var buf bytes.Buffer

	type item struct {
		Name string `json:"name"`
	}
	data := []item{{Name: "foo"}, {Name: "bar"}}

	if err := e.Write(&buf, data); err != nil {
		t.Fatal(err)
	}

	got := bytes.TrimSpace(buf.Bytes())
	if string(got) != "foo" {
		t.Errorf("expected %q, got %q", "foo", string(got))
	}
}

func TestExporterWrite_WithJQ_InvalidExpr(t *testing.T) {
	e := &Exporter{jq: ".[invalid"}
	var buf bytes.Buffer

	err := e.Write(&buf, []string{"a"})
	if err == nil {
		t.Fatal("expected error for invalid jq expression")
	}
}
