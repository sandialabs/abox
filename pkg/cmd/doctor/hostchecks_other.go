//go:build !darwin

package doctor

// platformHostChecks contributes no extra host checks on non-macOS platforms;
// the macOS build adds pf-anchor / vmnet-helper / vfkit diagnostics.
func platformHostChecks() []CheckResult { return nil }
