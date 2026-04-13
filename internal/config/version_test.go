package config

import (
	"strings"
	"testing"
)

func TestCheckVersion(t *testing.T) {
	tests := []struct {
		name       string
		version    int
		current    int
		configType string
		wantErr    bool
		errContain string
	}{
		{
			name:       "valid current version",
			version:    1,
			current:    1,
			configType: "test config",
			wantErr:    false,
		},
		{
			name:       "valid older version",
			version:    1,
			current:    2,
			configType: "test config",
			wantErr:    false,
		},
		{
			name:       "missing version",
			version:    0,
			current:    1,
			configType: "test config",
			wantErr:    true,
			errContain: "missing required 'version' field",
		},
		{
			name:       "newer than supported",
			version:    2,
			current:    1,
			configType: "test config",
			wantErr:    true,
			errContain: "newer than supported",
		},
		{
			name:       "error includes config type",
			version:    0,
			current:    1,
			configType: "instance config",
			wantErr:    true,
			errContain: "instance config",
		},
		{
			name:       "error includes versions",
			version:    5,
			current:    3,
			configType: "test",
			wantErr:    true,
			errContain: "version 5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckVersion(tt.version, tt.current, tt.configType)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errContain != "" {
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("CheckVersion() error = %q, want to contain %q", err.Error(), tt.errContain)
				}
			}
		})
	}
}

func TestCurrentVersionConstants(t *testing.T) {
	// Ensure constants are set to expected values
	if CurrentInstanceVersion != 1 {
		t.Errorf("CurrentInstanceVersion = %d, want 1", CurrentInstanceVersion)
	}
	if CurrentGlobalVersion != 1 {
		t.Errorf("CurrentGlobalVersion = %d, want 1", CurrentGlobalVersion)
	}
}
