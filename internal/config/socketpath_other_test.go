//go:build !darwin

package config

import (
	"strings"
	"testing"
)

func TestValidateSocketPaths_NoLimit(t *testing.T) {
	// Off darwin the check is a no-op even for an absurdly long path (see the
	// documented limitation in socketpath_other.go).
	long := &Paths{DNSSocket: "/run/user/1000/abox-" + strings.Repeat("n", 200) + "-dns.sock"}
	if err := ValidateSocketPaths(long); err != nil {
		t.Errorf("ValidateSocketPaths should be a no-op off darwin, got: %v", err)
	}
	if err := ValidateSocketPaths(nil); err != nil {
		t.Errorf("nil paths should be safe, got: %v", err)
	}
}
