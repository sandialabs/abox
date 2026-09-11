//go:build !linux && !darwin && !windows

package main

// No VM backends are registered on platforms other than Linux, macOS, and
// Windows (mirrors pkg/cmd/root/backends_other.go). The matrix still compiles;
// with an empty registry it simply has no backends to iterate.
