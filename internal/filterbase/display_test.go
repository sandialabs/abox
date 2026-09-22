package filterbase

import (
	"strings"
	"testing"
)

func TestStatusData_SecurityWarnings(t *testing.T) {
	tests := []struct {
		name string
		data StatusData
		want []string // substrings expected, in order; nil = no warnings
	}{
		{
			name: "http-secure-active-mitm",
			data: StatusData{FilterName: FilterHTTP, Mode: "active", MITM: true},
			want: nil,
		},
		{
			name: "http-passive",
			data: StatusData{FilterName: FilterHTTP, Mode: ModePassive, MITM: true},
			want: []string{"PASSIVE mode"},
		},
		{
			name: "http-mitm-disabled",
			data: StatusData{FilterName: FilterHTTP, Mode: "active", MITM: false},
			want: []string{"MITM is disabled"},
		},
		{
			name: "http-passive-and-mitm-off",
			data: StatusData{FilterName: FilterHTTP, Mode: ModePassive, MITM: false},
			want: []string{"PASSIVE mode", "MITM is disabled"},
		},
		{
			name: "dns-active",
			data: StatusData{FilterName: "DNS", Mode: "active"},
			want: nil,
		},
		{
			name: "dns-passive",
			data: StatusData{FilterName: "DNS", Mode: ModePassive},
			want: []string{"PASSIVE mode"},
		},
		{
			// DNS has no MITM concept, so MITM=false must not add a warning.
			name: "dns-no-mitm-warning",
			data: StatusData{FilterName: "DNS", Mode: "active", MITM: false},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.data.SecurityWarnings()
			if len(got) != len(tt.want) {
				t.Fatalf("SecurityWarnings() = %v, want %d warnings", got, len(tt.want))
			}
			for i, sub := range tt.want {
				if !strings.Contains(got[i], sub) {
					t.Errorf("warning[%d] = %q, want substring %q", i, got[i], sub)
				}
			}
		})
	}
}
