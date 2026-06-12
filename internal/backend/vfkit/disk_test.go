//go:build darwin

package vfkit

import (
	"testing"
)

func TestParseDiskSize(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int64
		wantErr bool
	}{
		{"1G", "1G", 1024 * 1024 * 1024, false},
		{"20G", "20G", 20 * 1024 * 1024 * 1024, false},
		{"100M", "100M", 100 * 1024 * 1024, false},
		{"512K", "512K", 512 * 1024, false},
		{"1T", "1T", 1024 * 1024 * 1024 * 1024, false},
		{"lowercase_g", "20g", 20 * 1024 * 1024 * 1024, false},
		{"empty", "", 0, true},
		{"no_suffix", "20", 0, true},
		{"single_char", "G", 0, true},
		{"bad_number", "abcG", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDiskSize(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDiskSize(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseDiskSize(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}
