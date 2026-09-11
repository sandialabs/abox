//go:build darwin

package doctor

import (
	"os/exec"

	"github.com/sandialabs/abox/internal/privilege"
	"github.com/sandialabs/abox/internal/vmnethelper"
)

// Names for the macOS-only host checks. On macOS the egress path depends on
// three host-level prerequisites that a fresh machine won't have: the abox pf
// anchors wired into /etc/pf.conf, the vmnet-helper binary, and the vfkit
// binary. Surfacing them in `abox doctor` turns the three most common first-run
// failures into actionable diagnostics.
const (
	checkNamePfAnchors   = "PF anchors wired"
	checkNameVmnetHelper = "vmnet-helper installed"
	checkNameVfkit       = "vfkit installed"
	checkNameQemuImg     = "qemu-img installed"
	checkNameXorriso     = "xorriso installed"
)

// platformHostChecks returns macOS-specific host diagnostics appended to the
// host-check phase. All are read-only and require no privileges. qemu-img and
// xorriso are also declared by the vfkit backend's RequiredTools() and covered by
// `abox check-deps`; they are surfaced here too so `abox doctor` is a complete
// first-run picture of the vfkit prerequisites.
func platformHostChecks() []CheckResult {
	return []CheckResult{
		checkPfAnchorsWired(),
		checkVmnetHelperInstalled(),
		checkVfkitInstalled(),
		checkBinaryOnPath(checkNameQemuImg, "qemu-img", "install with `brew install qemu`"),
		checkBinaryOnPath(checkNameXorriso, "xorriso", "install with `brew install xorriso`"),
	}
}

// checkBinaryOnPath reports whether bin resolves on PATH, attaching hint when not.
func checkBinaryOnPath(name, bin, hint string) CheckResult {
	result := CheckResult{Name: name}
	path, err := exec.LookPath(bin)
	if err != nil {
		result.Details = "not found on PATH"
		result.Hint = hint
		return result
	}
	result.Passed = true
	result.Details = path
	return result
}

// checkPfAnchorsWired reports whether the abox rdr/filter anchor references are
// present in /etc/pf.conf. When absent it distinguishes an auto-wireable
// stock pf.conf (the next `abox start` fixes it) from a customized one that
// needs a manual edit.
func checkPfAnchorsWired() CheckResult {
	result := CheckResult{Name: checkNamePfAnchors}

	wired, err := privilege.HasAnchorReferences(privilege.PfconfDefaultPath)
	if err != nil {
		result.Details = "cannot read " + privilege.PfconfDefaultPath + ": " + err.Error()
		result.Hint = "abox will wire the anchors on the next `abox start`"
		return result
	}
	if wired {
		result.Passed = true
		result.Details = "abox anchors referenced in " + privilege.PfconfDefaultPath
		return result
	}

	result.Details = "abox anchors not yet referenced in " + privilege.PfconfDefaultPath
	if canWire, wErr := privilege.CanAutoWireAnchors(privilege.PfconfDefaultPath); wErr == nil && canWire {
		result.Hint = "the next `abox start` will wire them automatically"
	} else {
		result.Hint = "customized pf.conf: add `rdr-anchor \"abox/*\"` and `anchor \"abox/*\"` manually"
	}
	return result
}

// checkVmnetHelperInstalled reports whether the vmnet-helper binary resolves.
func checkVmnetHelperInstalled() CheckResult {
	result := CheckResult{Name: checkNameVmnetHelper}
	path, err := vmnethelper.ResolveBinaryPath()
	if err != nil {
		result.Details = "not found"
		result.Hint = err.Error()
		return result
	}
	result.Passed = true
	result.Details = path
	return result
}

// checkVfkitInstalled reports whether the vfkit binary is on PATH.
func checkVfkitInstalled() CheckResult {
	result := CheckResult{Name: checkNameVfkit}
	path, err := exec.LookPath("vfkit")
	if err != nil {
		result.Details = "not found on PATH"
		result.Hint = "install with `brew install vfkit`"
		return result
	}
	result.Passed = true
	result.Details = path
	return result
}
