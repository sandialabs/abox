package cmdutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/itchyny/gojq"
	"github.com/spf13/cobra"
)

// Exporter writes JSON output when --json is set, with optional --jq filtering.
type Exporter struct {
	enabled bool
	jq      string
}

// Enabled reports whether JSON output was requested (--json or --jq).
func (e *Exporter) Enabled() bool {
	return e.enabled || e.jq != ""
}

// Write marshals data as indented JSON to w.
// If --jq is set, the output is filtered using gojq.
func (e *Exporter) Write(w io.Writer, data any) error {
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	if e.jq != "" {
		return applyJQ(w, buf.Bytes(), e.jq)
	}

	_, err := buf.WriteTo(w)
	return err
}

// AddJSONFlags registers --json and --jq flags on cmd and returns an Exporter.
func AddJSONFlags(cmd *cobra.Command) *Exporter {
	e := &Exporter{}
	cmd.Flags().BoolVar(&e.enabled, "json", false, "Output as JSON")
	cmd.Flags().StringVar(&e.jq, "jq", "", "Filter JSON output with a jq expression (implies --json)")
	return e
}

// applyJQ filters jsonData through gojq with the given expression.
func applyJQ(w io.Writer, jsonData []byte, expr string) error {
	query, err := gojq.Parse(expr)
	if err != nil {
		return FlagErrorf("invalid --jq expression: %w", err)
	}
	var input any
	if err := json.Unmarshal(jsonData, &input); err != nil {
		return err
	}
	iter := query.Run(input)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if err, ok := v.(error); ok {
			return FlagErrorf("--jq error: %w", err)
		}
		// Suppress nil and false (standard jq behavior for select()).
		if v == nil || v == false {
			continue
		}
		if s, ok := v.(string); ok {
			fmt.Fprintln(w, s)
		} else {
			if err := enc.Encode(v); err != nil {
				return err
			}
		}
	}
	return nil
}
