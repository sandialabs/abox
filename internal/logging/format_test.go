package logging

import (
	"log/slog"
	"testing"
)

// TestFormatValue tests the formatValue helper function.
func TestFormatValue(t *testing.T) {
	tests := []struct {
		name     string
		value    slog.Value
		expected string
	}{
		{
			name:     "simple string",
			value:    slog.StringValue("hello"),
			expected: "hello",
		},
		{
			name:     "string with spaces",
			value:    slog.StringValue("hello world"),
			expected: `"hello world"`,
		},
		{
			name:     "integer",
			value:    slog.IntValue(42),
			expected: "42",
		},
		{
			name:     "boolean",
			value:    slog.BoolValue(true),
			expected: "true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatValue(tt.value)
			if result != tt.expected {
				t.Errorf("formatValue(%v) = %q, want %q", tt.value, result, tt.expected)
			}
		})
	}
}
