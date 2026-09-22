//go:build !linux

package privilege

import (
	"os/exec"
	"testing"
)

// TestSetRootCredentialFailsClosed verifies the non-Linux stub refuses to
// configure a root credential rather than silently spawning a privileged child
// with the calling user's credentials. The setuid egress helper is Linux-only,
// so every off-Linux attempt must return an error (fail closed).
func TestSetRootCredentialFailsClosed(t *testing.T) {
	cmd := exec.Command("true")
	if err := setRootCredential(cmd); err == nil {
		t.Fatal("expected an error from the non-Linux setRootCredential stub, got nil")
	}
	if cmd.SysProcAttr != nil {
		t.Fatal("expected SysProcAttr to remain unset when the credential is unsupported")
	}
}
