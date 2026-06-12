//go:build darwin

package tap

import (
	"testing"

	"github.com/sandialabs/abox/internal/config"
)

func TestCaptureInterfaceDarwin(t *testing.T) {
	tests := []struct {
		name      string
		inst      *config.Instance
		wantIface string
		wantErr   bool
	}{
		{
			name: "valid bridge in BackendConfig",
			inst: &config.Instance{
				Name: "dev",
				BackendConfig: map[string]any{
					"bridge": "bridge100",
				},
			},
			wantIface: "bridge100",
		},
		{
			name: "nil BackendConfig",
			inst: &config.Instance{
				Name: "dev",
			},
			wantErr: true,
		},
		{
			name: "BackendConfig missing bridge key",
			inst: &config.Instance{
				Name:          "dev",
				BackendConfig: map[string]any{},
			},
			wantErr: true,
		},
		{
			name: "BackendConfig bridge is empty string",
			inst: &config.Instance{
				Name: "dev",
				BackendConfig: map[string]any{
					"bridge": "",
				},
			},
			wantErr: true,
		},
		{
			name: "BackendConfig bridge is wrong type (int)",
			inst: &config.Instance{
				Name: "dev",
				BackendConfig: map[string]any{
					"bridge": 42,
				},
			},
			// int → string type-assert yields "" → treated as empty
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := captureInterface(tt.inst)
			if tt.wantErr {
				if err == nil {
					t.Errorf("captureInterface() error = nil, want non-nil error")
				}
				return
			}
			if err != nil {
				t.Errorf("captureInterface() unexpected error: %v", err)
				return
			}
			if got != tt.wantIface {
				t.Errorf("captureInterface() = %q, want %q", got, tt.wantIface)
			}
		})
	}
}
