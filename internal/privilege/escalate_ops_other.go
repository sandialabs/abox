//go:build !unix

package privilege

import "errors"

// The one-shot migrate escalation relies on unix uid/gid ownership and the
// install/mv/chown coreutils run under sudo/pkexec. None of that exists on
// non-unix platforms (Windows), and there is no libvirt storage to migrate
// there, so every operation fails closed rather than pretend to relocate
// root-owned files.
var errEscalateUnsupported = errors.New("privileged file relocation is not supported on this platform")

// RunEscalated is unsupported off unix.
func RunEscalated(_ string, _ ...string) error { return errEscalateUnsupported }

// CopyAsUser is unsupported off unix.
func CopyAsUser(_, _, _ string) error { return errEscalateUnsupported }

// MoveAsUser is unsupported off unix.
func MoveAsUser(_, _, _ string) error { return errEscalateUnsupported }

// ChownRecursiveAsUser is unsupported off unix.
func ChownRecursiveAsUser(_, _ string) error { return errEscalateUnsupported }
