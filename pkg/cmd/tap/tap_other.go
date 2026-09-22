//go:build !darwin

package tap

import (
	"os"
	"os/exec"
	"strings"

	"github.com/sandialabs/abox/internal/config"
)

// tcpdumpInstallHint is appended to the Long help text. On Linux tcpdump must
// usually be installed from the distro package manager.
const tcpdumpInstallHint = `

Requires tcpdump to be installed (sudo apt install tcpdump). On most
Linux distributions, tcpdump has the necessary capture permissions by
default. If not, see the error message for remediation steps.`

// tcpdumpNotFoundHint is shown when tcpdump is not on PATH.
const tcpdumpNotFoundHint = "Install tcpdump: sudo apt install tcpdump"

// resolveCaptureInterface returns the host interface to capture on. On Linux
// the instance's bridge is a real host interface, so it is used directly.
func resolveCaptureInterface(inst *config.Instance) (string, error) {
	return inst.Bridge, nil
}

// needsEscalation checks whether tcpdump needs privilege escalation to capture.
func needsEscalation(tcpdumpBin string) bool {
	if os.Getuid() == 0 {
		return false
	}
	out, err := exec.Command("getcap", tcpdumpBin).Output()
	if err != nil {
		return true
	}
	s := string(out)
	return !strings.Contains(s, "cap_net_raw") || !strings.Contains(s, "cap_net_admin")
}

// hintForTcpdumpError returns a remediation hint for common tcpdump failures.
func hintForTcpdumpError(tcpdumpBin string) string {
	var hints []string
	hints = append(hints, "This may be a permission issue. Try:")
	hints = append(hints, "  sudo setcap cap_net_raw,cap_net_admin=eip "+tcpdumpBin)
	hints = append(hints, "If using a BPF filter, check the filter syntax.")
	return strings.Join(hints, "\n")
}

// privilegeFailureHint is returned when no privilege escalation tool is
// available to run tcpdump.
func privilegeFailureHint(tcpdumpBin string) string {
	return "Grant tcpdump capabilities:\n  sudo setcap cap_net_raw,cap_net_admin=eip " + tcpdumpBin
}
