//go:build darwin

package checkdeps

import (
	"fmt"
	"os/exec"
	"os/user"
	"regexp"
	"strconv"
	"strings"

	"github.com/sandialabs/abox/internal/vmnethelper"
)

// depVmnetHelper is the tool name the vfkit backend declares for its
// host-mode vmnet networking helper. It installs OFF PATH (into a Homebrew
// libexec dir), so the generic exec.LookPath check would wrongly report it
// missing. Keep this in sync with the backend's Tool.Name.
const depVmnetHelper = "vmnet-helper"

// depVfkit is the tool name the vfkit backend declares for the hypervisor
// itself. Kept in sync with the backend's Tool.Name.
const depVfkit = "vfkit"

// platformResolveTool special-cases macOS tools that need more than a PATH
// check: vmnet-helper installs off PATH and must be launched via passwordless
// sudo, and vfkit must be recent enough to support the unixSocketPath network
// device. For every other tool it returns not-ok so checkOne falls back to the
// generic PATH check.
func platformResolveTool(name string) (path string, ok bool, note string) {
	switch name {
	case depVmnetHelper:
		return resolveVmnetHelper()
	case depVfkit:
		return resolveVfkit()
	case depSSHFS:
		return resolveSSHFS()
	default:
		return "", false, ""
	}
}

// resolveSSHFS resolves sshfs on macOS. sshfs is not in Homebrew core, so when it
// is missing we attach the exact install commands. We recommend fuse-t, a
// kext-less FUSE implementation (it bridges to a local NFS server instead of a
// kernel extension, so there is no System Extension to approve and no reboot),
// over macFUSE. The fuse-t-sshfs cask still provides an `sshfs` binary, so this
// plain PATH check is unchanged. ok is always true so checkOne shows the note.
func resolveSSHFS() (path string, ok bool, note string) {
	resolved, err := exec.LookPath(depSSHFS)
	if err != nil {
		return "", true, "install the kext-less fuse-t (recommended over macFUSE): " +
			"brew tap macos-fuse-t/homebrew-cask && brew install fuse-t fuse-t-sshfs"
	}
	return resolved, true, ""
}

// resolveVmnetHelper resolves vmnet-helper (installed off PATH) with the same
// resolver the backend uses at runtime, and — on macOS versions that still
// require root (15 and earlier) — probes for a passwordless sudoers entry with
// `sudo -n -l <path>`, which asks sudo whether the invoking user may run that
// exact command WITHOUT executing it. If that fails, it emits the exact NOPASSWD
// sudoers line to add, pinning the absolute path.
func resolveVmnetHelper() (path string, ok bool, note string) {
	resolved, err := vmnethelper.ResolveBinaryPath()
	if err != nil {
		// Not found: report as missing (path empty) but ok=true so checkOne
		// uses this result rather than the misleading generic LookPath.
		return "", true, "install with: brew tap nirs/vmnet-helper && brew trust nirs/vmnet-helper && brew install vmnet-helper (brew trust needed on Homebrew 6.0.0+)"
	}

	// macOS 26+ does not require root for vmnet-helper, so no sudoers entry is
	// needed. Only probe/advise on versions that still need sudo.
	if !vmnethelper.NeedsSudo() {
		return resolved, true, ""
	}

	if passwordlessSudoOK(resolved) {
		return resolved, true, ""
	}

	return resolved, true, sudoersNote(resolved)
}

// resolveVfkit resolves vfkit on PATH and attaches an informational note with
// its version. abox connects the guest NIC to vmnet-helper over a unix datagram
// socket (`--device virtio-net,unixSocketPath=`), so a vfkit too old to support
// that device leaves the guest unreachable — but every current build (Homebrew
// ships >= the floor below) supports it, so we only warn when we can positively
// prove the installed version is too old. Presence is what gates check-deps.
func resolveVfkit() (path string, ok bool, note string) {
	resolved, err := exec.LookPath(depVfkit)
	if err != nil {
		// Not on PATH: let the generic check report it missing.
		return "", false, ""
	}
	return resolved, true, vfkitVersionNote(resolved)
}

// minVfkitVersion is the oldest vfkit known to carry the unixSocketPath datagram
// datapath abox relies on, including the "path too long" fix for those sockets
// (crc-org/vfkit#195) — abox's per-instance socket paths can approach the
// sun_path limit. Homebrew ships newer; anything below this gets an advisory
// upgrade note. It is a conservative floor, not a hard gate: a too-old vfkit is
// still non-fatal here (presence gates check-deps) and its real failure surfaces
// as an unreachable guest in the vfkit log tail after `abox start`.
var minVfkitVersion = [3]int{0, 6, 0}

// vfkitVersionRE pulls a dotted major.minor(.patch) out of a `vfkit --version`
// line such as "vfkit version: v0.6.4". Patch is optional.
var vfkitVersionRE = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)

// vfkitVersionNote returns the first line of `vfkit --version` as an
// informational note, appending an upgrade warning only when the version parses
// and is demonstrably older than minVfkitVersion. Versions at/above the floor
// (the common case) get just the version line — no warning. If the version can't
// be read or parsed we stay silent rather than cry wolf on a fine-but-unusual
// build; the runtime log tail remains the real safety net.
func vfkitVersionNote(path string) string {
	const req = "host networking needs `--device virtio-net,unixSocketPath=` support; upgrade vfkit if `abox start` reports the guest unreachable"
	out, err := exec.Command(path, "--version").CombinedOutput()
	v := strings.TrimSpace(string(out))
	if err != nil || v == "" {
		return ""
	}
	if i := strings.IndexByte(v, '\n'); i >= 0 {
		v = v[:i]
	}
	if ver, ok := parseVfkitVersion(v); ok && versionLess(ver, minVfkitVersion) {
		return fmt.Sprintf("%s — older than v%d.%d.%d; %s",
			v, minVfkitVersion[0], minVfkitVersion[1], minVfkitVersion[2], req)
	}
	return v
}

// parseVfkitVersion extracts major.minor.patch from a version line. ok is false
// when no dotted version is present.
func parseVfkitVersion(s string) (v [3]int, ok bool) {
	m := vfkitVersionRE.FindStringSubmatch(s)
	if m == nil {
		return v, false
	}
	v[0], _ = strconv.Atoi(m[1])
	v[1], _ = strconv.Atoi(m[2])
	if m[3] != "" {
		v[2], _ = strconv.Atoi(m[3])
	}
	return v, true
}

// versionLess reports whether a < b comparing major, then minor, then patch.
func versionLess(a, b [3]int) bool {
	for i := range 3 {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// passwordlessSudoOK reports whether a passwordless sudoers entry exists for
// the resolved vmnet-helper path. It probes with `sudo -n -l <path>`, which asks
// sudo whether the invoking user may run that exact command and exits 0 only if
// a matching rule exists that is satisfiable non-interactively (NOPASSWD). It
// never executes vmnet-helper, so the result does not depend on the binary's
// flags/behavior and never touches the vmnet device; -n guarantees no prompt.
func passwordlessSudoOK(path string) bool {
	return exec.Command("sudo", "-n", "-l", path).Run() == nil
}

// sudoersNote returns guidance telling the user to add a NOPASSWD sudoers line
// pinning the absolute vmnet-helper path.
func sudoersNote(path string) string {
	who := "<user>"
	if u, err := user.Current(); err == nil && u.Username != "" {
		who = u.Username
	}
	return fmt.Sprintf(
		"needs passwordless sudo; add to sudoers (via `sudo visudo`):\n"+
			"               %s ALL=(root) NOPASSWD: %s",
		who, path)
}
