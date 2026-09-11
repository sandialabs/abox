//go:build !unix

package images

import "os"

// lockFile and unlockFile are no-ops on platforms without advisory file locking
// (currently Windows). The base-image lock only serializes concurrent abox
// processes cloning from / removing a shared base image, and there is no VM
// backend on Windows yet, so nothing there produces the concurrent access the
// lock guards against. A real implementation (LockFileEx via
// golang.org/x/sys/windows) should accompany a Windows backend. Making these
// no-ops lets the package cross-compile there.
//
// Darwin is NOT affected: it satisfies the `unix` build tag, so it compiles the
// real flock implementation in lock_unix.go, not this stub.
//
// TODO(windows-backend): a Windows VM backend needs real advisory locking here —
// this no-op silently disables the base-image concurrency guard.
func lockFile(_ *os.File, _ LockMode) error { return nil }

func unlockFile(_ *os.File) error { return nil }
