//go:build darwin

package doctor

import (
	"github.com/sandialabs/abox/internal/privilege"
)

// checkPfAnchorsWired reports whether the given pf.conf references the abox/*
// anchors. Without this reference, per-instance pf rules are loaded but
// never evaluated by the kernel. The check is read-only (pf.conf is mode
// 0644 by default), so no privilege escalation is required.
//
// When the references are missing, distinguish between:
//   - "not wired yet" (Apple markers present → next abox start auto-wires)
//   - "custom pf.conf" (Apple markers absent → user must edit manually)
//
// so the user gets an actionable hint either way.
//
// pfconfPath is a parameter (not the constant) for testability; production
// callers go through platformHostChecks which passes privilege.PfconfDefaultPath.
func checkPfAnchorsWired(pfconfPath string) CheckResult {
	result := CheckResult{Name: "PF anchors wired in " + pfconfPath}

	wired, err := privilege.HasAnchorReferences(pfconfPath)
	if err != nil {
		result.Details = err.Error()
		result.Hint = "Could not read " + pfconfPath
		return result
	}

	if wired {
		result.Passed = true
		return result
	}

	canAutoWire, err := privilege.CanAutoWireAnchors(pfconfPath)
	if err != nil {
		// Same file, same read — shouldn't happen, but fall back to the
		// generic hint if it does.
		result.Details = "abox anchor references missing"
		result.Hint = "Run `abox start <instance>` to wire them automatically."
		return result
	}

	if canAutoWire {
		result.Details = "abox anchor references missing"
		result.Hint = "Run `abox start <instance>` to wire them automatically."
		return result
	}

	result.Details = "abox anchor references missing, and " + pfconfPath +
		" lacks the standard Apple anchors abox piggybacks on"
	result.Hint = "pf.conf appears custom or MDM-managed. Add `rdr-anchor \"abox/*\"` " +
		"to the translation section and `anchor \"abox/*\"` to the filter section manually."
	return result
}

// platformHostChecks returns macOS-specific host checks appended to Phase 1.
func platformHostChecks() []CheckResult {
	return []CheckResult{checkPfAnchorsWired(privilege.PfconfDefaultPath)}
}
