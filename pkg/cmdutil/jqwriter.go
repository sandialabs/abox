package cmdutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/itchyny/gojq"
)

// JQWriter wraps an io.Writer and filters each NDJSON line through a gojq
// expression. Non-JSON lines pass through unchanged. It implements io.Writer.
type JQWriter struct {
	w     io.Writer
	query *gojq.Query
	buf   bytes.Buffer
}

// NewJQWriter creates a JQWriter that filters each JSON line through expr.
// Returns a FlagError on invalid jq expression.
func NewJQWriter(w io.Writer, expr string) (*JQWriter, error) {
	query, err := gojq.Parse(expr)
	if err != nil {
		return nil, FlagErrorf("invalid --jq expression: %w", err)
	}
	return &JQWriter{w: w, query: query}, nil
}

// Write buffers input and processes each complete line.
func (j *JQWriter) Write(p []byte) (int, error) {
	j.buf.Write(p)
	for {
		line, err := j.buf.ReadBytes('\n')
		if err != nil {
			// Incomplete line — put it back for next Write or Flush.
			j.buf.Write(line)
			break
		}
		if err := j.processLine(line); err != nil {
			return len(p), err
		}
	}
	return len(p), nil //nolint:nilerr // ReadBytes returns io.EOF for incomplete lines; data is buffered for next Write
}

// Flush processes any remaining buffered content.
func (j *JQWriter) Flush() error {
	if j.buf.Len() == 0 {
		return nil
	}
	remaining := j.buf.Bytes()
	j.buf.Reset()
	return j.processLine(remaining)
}

// processLine handles a single line: JSON lines are filtered through gojq,
// non-JSON lines pass through unchanged.
func (j *JQWriter) processLine(line []byte) error {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		_, err := j.w.Write(line)
		return err
	}

	var input any
	if err := json.Unmarshal(trimmed, &input); err != nil {
		// Not JSON — pass through unchanged.
		_, werr := j.w.Write(line)
		return werr
	}

	iter := j.query.Run(input)
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if err, ok := v.(error); ok {
			return FlagErrorf("--jq error: %w", err)
		}
		// Suppress nil and false (standard jq behavior).
		if v == nil || v == false {
			continue
		}
		if s, ok := v.(string); ok {
			fmt.Fprintln(j.w, s)
		} else {
			out, err := json.Marshal(v)
			if err != nil {
				return err
			}
			if _, err := j.w.Write(append(out, '\n')); err != nil {
				return err
			}
		}
	}
	return nil
}
