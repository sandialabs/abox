//go:build darwin

package tap

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/sandialabs/abox/internal/config"
)

// tcpdumpInstallHint is appended to the Long help text on Darwin.
// tcpdump ships with macOS, so no package installation is needed.
const tcpdumpInstallHint = `

tcpdump ships with macOS. Capturing on the vmnet bridge interface
(e.g. bridge100) requires access to /dev/bpf* devices, which are
root-only by default; abox escalates via sudo automatically.`

// captureInterface returns the real vmnet bridge interface name (e.g. "bridge100")
// that VMManager.Start persisted into BackendConfig["bridge"] after the VM booted.
// The logical resource name in inst.Bridge (e.g. "abox-dev") is not a host interface
// on macOS and will fail with "no such device" if passed to tcpdump directly.
func captureInterface(inst *config.Instance) (string, error) {
	if inst.BackendConfig == nil {
		return "", errors.New("no backend config recorded; is the instance started with the vfkit backend?")
	}
	v, ok := inst.BackendConfig["bridge"]
	if !ok {
		return "", fmt.Errorf("bridge interface not recorded for instance %q; "+
			"start the instance before running tap", inst.Name)
	}
	s, _ := v.(string)
	if s == "" {
		return "", fmt.Errorf("bridge interface for instance %q is empty; "+
			"start the instance before running tap", inst.Name)
	}
	return s, nil
}

// needsEscalation reports whether tcpdump requires privilege escalation.
// On macOS, access to /dev/bpf* is root-only unless ChmodBPF (e.g. from
// Wireshark) has been installed. We probe /dev/bpf0 directly: EBUSY means
// another process has the device open, which still indicates we have
// permission (tcpdump will move to the next /dev/bpfN device automatically).
// Any other open error → assume escalation is needed.
func needsEscalation(_ string) bool {
	if os.Getuid() == 0 {
		return false
	}
	f, err := os.Open("/dev/bpf0")
	if err == nil {
		_ = f.Close()
		return false
	}
	// EBUSY: another process has /dev/bpf0 open; we still have access rights.
	var pathErr *os.PathError
	if errors.As(err, &pathErr) && errors.Is(pathErr.Err, syscall.EBUSY) {
		return false
	}
	return true
}

// hintForTcpdumpError returns a remediation hint for common tcpdump failures
// on macOS.
func hintForTcpdumpError(_ string) string {
	return "This may be a /dev/bpf access issue.\n" +
		"abox escalates via sudo automatically; if that also failed,\n" +
		"check that sudo is available and your account has sudo access.\n" +
		"Alternatively, install Wireshark (which includes ChmodBPF) to\n" +
		"grant your user account /dev/bpf access without sudo."
}

// tcpdumpNotFoundHint is returned when tcpdump is not found on macOS.
const tcpdumpNotFoundHint = "tcpdump ships with macOS; check that /usr/sbin is on your PATH"

// privilegeFailureHint is returned when privilege escalation fails on macOS.
func privilegeFailureHint(_ string) string {
	return "tcpdump requires /dev/bpf access (root-only by default on macOS).\n" +
		"Ensure sudo is available, or install Wireshark (ChmodBPF) to grant\n" +
		"your user account access to /dev/bpf* without sudo."
}
