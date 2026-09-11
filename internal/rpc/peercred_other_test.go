//go:build !linux && !darwin

package rpc

import (
	"errors"
	"testing"
)

// TestGetPeerCredentialsUnsupported verifies the stub (platforms without a
// native peer-auth mechanism) returns ErrPeerAuthUnsupported and never
// (0, 0, nil) — which uidCheckListener would treat as root. darwin is excluded
// because it has a real LOCAL_PEERCRED implementation (see peercred_darwin_test.go).
func TestGetPeerCredentialsUnsupported(t *testing.T) {
	pid, uid, err := GetPeerCredentials(nil)
	if !errors.Is(err, ErrPeerAuthUnsupported) {
		t.Fatalf("expected ErrPeerAuthUnsupported from the stub, got: %v", err)
	}
	if pid != 0 || uid != 0 {
		t.Fatalf("expected zero pid/uid on error, got pid=%d uid=%d", pid, uid)
	}
}
