package tap

import "testing"

func TestBuildBPFFilter(t *testing.T) {
	tests := []struct {
		name       string
		userFilter string
		gateway    string
		includeSSH bool
		want       string
	}{
		{
			name:    "default excludes SSH",
			gateway: "10.10.10.1",
			want:    "not (tcp port 22 and host 10.10.10.1)",
		},
		{
			name:       "include-ssh disables exclusion",
			gateway:    "10.10.10.1",
			includeSSH: true,
			want:       "",
		},
		{
			name:       "user filter only when include-ssh",
			userFilter: "tcp port 443",
			gateway:    "10.10.10.1",
			includeSSH: true,
			want:       "(tcp port 443)",
		},
		{
			name:       "combined default plus user filter",
			userFilter: "tcp port 443",
			gateway:    "10.10.10.1",
			want:       "not (tcp port 22 and host 10.10.10.1) and (tcp port 443)",
		},
		{
			name:       "user filter with or is parenthesized",
			userFilter: "tcp port 443 or udp port 53",
			gateway:    "10.10.10.1",
			want:       "not (tcp port 22 and host 10.10.10.1) and (tcp port 443 or udp port 53)",
		},
		{
			name: "empty gateway skips exclusion",
			want: "",
		},
		{
			name:       "empty gateway with user filter",
			userFilter: "udp port 53",
			want:       "(udp port 53)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildBPFFilter(tt.userFilter, tt.gateway, tt.includeSSH)
			if got != tt.want {
				t.Errorf("buildBPFFilter(%q, %q, %v) = %q, want %q",
					tt.userFilter, tt.gateway, tt.includeSSH, got, tt.want)
			}
		})
	}
}
