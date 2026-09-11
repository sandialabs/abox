//go:build unix

package privilege

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

// This file holds the one-shot, interactive privilege escalation used by `abox
// migrate` to relocate root-owned legacy files. It is DELIBERATELY separate from
// the long-running gRPC privilege helper (helper.go / client.go): that
// helper is a daemon-style, token-authenticated channel for runtime network
// operations, whereas these are a single sudo/pkexec invocation for a one-time
// admin task that wires the terminal through so the user can type a password.

// RunEscalated runs a single command under sudo/pkexec, wiring the terminal so
// the tool can prompt for a password. tool is the value returned by
// SelectEscalationTool.
func RunEscalated(tool string, args ...string) error {
	cmd := exec.Command(tool, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %v failed: %w", tool, args, err)
	}
	return nil
}

// CopyAsUser copies src to dst as root and gives ownership to the calling user,
// in a single privileged invocation.
func CopyAsUser(tool, src, dst string) error {
	return RunEscalated(tool, "install", "-m", "600",
		"-o", strconv.Itoa(os.Getuid()), "-g", strconv.Itoa(os.Getgid()),
		src, dst)
}

// MoveAsUser moves src to dst as root, then hands the moved tree to the calling
// user.
func MoveAsUser(tool, src, dst string) error {
	if err := RunEscalated(tool, "mv", src, dst); err != nil {
		return err
	}
	return ChownRecursiveAsUser(tool, dst)
}

// ChownRecursiveAsUser recursively chowns dst to the calling user. It is
// idempotent, so it can be re-run to recover a move that completed but whose
// ownership step did not.
func ChownRecursiveAsUser(tool, dst string) error {
	owner := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
	return RunEscalated(tool, "chown", "-R", owner, dst)
}
