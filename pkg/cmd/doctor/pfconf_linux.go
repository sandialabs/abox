//go:build linux

package doctor

// platformHostChecks is a no-op on Linux; PF anchors only apply to macOS.
func platformHostChecks() []CheckResult { return nil }
