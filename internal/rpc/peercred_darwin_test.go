//go:build darwin

package rpc

import "testing"

func TestValidateXucred_VersionMismatchFailsClosed(t *testing.T) {
	// A structure version that does not match what we compiled against must be
	// rejected, even if the UID looks like a normal user. Trusting it would let
	// an attacker who can influence the returned structure masquerade as another
	// user (including uid 0).
	if _, err := validateXucred(xucredVersion0+1, 1000); err == nil {
		t.Fatalf("expected error on version mismatch, got nil")
	}
}

func TestValidateXucred_ValidVersionReturnsUID(t *testing.T) {
	uid, err := validateXucred(xucredVersion0, 501)
	if err != nil {
		t.Fatalf("unexpected error for valid version: %v", err)
	}
	if uid != 501 {
		t.Fatalf("uid = %d, want 501", uid)
	}
}

func TestValidateXucred_RootUIDStillRequiresValidVersion(t *testing.T) {
	// Fail-closed check specifically for uid 0: a mismatched version must not be
	// silently accepted as root.
	if _, err := validateXucred(0xdeadbeef, 0); err == nil {
		t.Fatalf("expected error rejecting uid 0 with bad version, got nil")
	}
}

// TestGetPeerCredentialsRejectsNonUnixConn verifies the real darwin
// LOCAL_PEERCRED implementation fails closed on a non-unix connection (here nil)
// rather than returning (0, 0, nil), which uidCheckListener would treat as root.
func TestGetPeerCredentialsRejectsNonUnixConn(t *testing.T) {
	pid, uid, err := GetPeerCredentials(nil)
	if err == nil {
		t.Fatal("expected an error for a non-unix connection, got nil")
	}
	if pid != 0 || uid != 0 {
		t.Fatalf("expected zero pid/uid on error, got pid=%d uid=%d", pid, uid)
	}
}
