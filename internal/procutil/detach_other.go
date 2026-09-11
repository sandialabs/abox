//go:build !unix

package procutil

import "os/exec"

// Detach is a no-op on platforms without POSIX process groups (Windows). Windows
// child processes do not share the parent's controlling terminal the way unix
// ones do, so no explicit detach is required for a spawned daemon to outlive its
// launcher; a full implementation would use CREATE_NEW_PROCESS_GROUP via
// SysProcAttr and belongs alongside a Windows backend.
//
// Darwin is NOT affected: it satisfies the `unix` build tag, so it compiles the
// real Setpgid implementation in detach_unix.go, not this stub.
//
// TODO(windows-backend): revisit before a Windows backend spawns long-lived
// daemons — this no-op assumes no detach is needed on Windows.
func Detach(_ *exec.Cmd) {}
