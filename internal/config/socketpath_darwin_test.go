//go:build darwin

package config

import (
	"strings"
	"testing"
)

func TestValidateSocketPaths_Darwin(t *testing.T) {
	short := &Paths{
		DNSSocket:        "/tmp/abox-dev-dns.sock",
		HTTPSocket:       "/tmp/abox-dev-http.sock",
		MonitorRPCSocket: "/tmp/abox-dev-monitor.sock",
		MonitorSocket:    "/tmp/abox-dev/monitor.sock",
	}
	if err := ValidateSocketPaths(short); err != nil {
		t.Errorf("short socket paths should pass, got: %v", err)
	}

	long := &Paths{
		DNSSocket: "/var/folders/qx/" + strings.Repeat("a", 40) + "/T/abox-" +
			strings.Repeat("n", 60) + "-dns.sock",
	}
	err := ValidateSocketPaths(long)
	if err == nil {
		t.Fatal("overlong socket path should fail on darwin")
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Errorf("error should explain the length problem, got: %v", err)
	}
}
