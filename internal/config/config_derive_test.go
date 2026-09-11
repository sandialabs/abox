package config

import (
	"runtime"
	"testing"
)

func TestDeriveHostIP(t *testing.T) {
	tests := []struct {
		name    string
		gateway string
		want    string
	}{
		{"typical /24 gateway", "192.168.128.1", "192.168.128.10"},
		{"other subnet", "10.10.20.1", "10.10.20.10"},
		{"malformed returns empty", "garbage", ""},
		{"partial returns empty", "1.2", ""},
		{"empty returns empty", "", ""},
		{"ipv6 returns empty", "fd00::1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DeriveHostIP(tt.gateway); got != tt.want {
				t.Errorf("DeriveHostIP(%q) = %q, want %q", tt.gateway, got, tt.want)
			}
		})
	}
}

func TestUserBaseImageExtAndName(t *testing.T) {
	wantExt := ".qcow2"
	if runtime.GOOS == "darwin" {
		wantExt = ".raw"
	}
	if got := UserBaseImageExt(); got != wantExt {
		t.Errorf("UserBaseImageExt() = %q, want %q on %s", got, wantExt, runtime.GOOS)
	}
	if got, want := UserBaseImageName("ubuntu-24.04"), "ubuntu-24.04"+wantExt; got != want {
		t.Errorf("UserBaseImageName = %q, want %q", got, want)
	}
}
