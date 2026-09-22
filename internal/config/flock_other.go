//go:build !unix

package config

// lockFileExclusive and unlockFile are no-ops on Windows for now: there is no
// VM backend on Windows yet, so the data-directory lock that serializes
// concurrent abox processes has nothing to protect. A real implementation
// (LockFileEx via golang.org/x/sys/windows) should be added alongside a Windows
// backend.
func lockFileExclusive(_ uintptr) error { return nil }

func unlockFile(_ uintptr) error { return nil }
