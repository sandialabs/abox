//go:build linux

package tap

import (
	"os"
	"os/exec"
	"strings"

	"github.com/sandialabs/abox/internal/config"
)

// tcpdumpInstallHint is appended to the Long help text on Linux.
const tcpdumpInstallHint = `

Requires tcpdump to be installed (sudo apt install tcpdump). On most
Linux distributions, tcpdump has the necessary capture permissions by
default. If not, see the error message for remediation steps.`

// captureInterface returns the host interface name to pass to tcpdump -i.
// On Linux the bridge name stored in inst.Bridge is a real host interface
// (e.g. "abox-dev"), so it is returned as-is.
func captureInterface(inst *config.Instance) (string, error) {
	return inst.Bridge, nil
}

// needsEscalation reports whether tcpdump requires privilege escalation.
// On Linux it inspects the binary's capabilities via getcap; if getcap is
// not available (or the capability is absent) it assumes escalation is needed.
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

// hintForTcpdumpError returns a remediation hint for common tcpdump failures
// on Linux.
func hintForTcpdumpError(tcpdumpBin string) string {
	var hints []string
	hints = append(hints, "This may be a permission issue. Try:")
	hints = append(hints, "  sudo setcap cap_net_raw,cap_net_admin=eip "+tcpdumpBin)
	hints = append(hints, "If using a BPF filter, check the filter syntax.")
	return strings.Join(hints, "\n")
}

// tcpdumpNotFoundHint is returned when tcpdump is not found on Linux.
const tcpdumpNotFoundHint = "Install tcpdump: sudo apt install tcpdump"

// privilegeFailureHint is returned when privilege escalation fails on Linux.
func privilegeFailureHint(tcpdumpBin string) string {
	return "Grant tcpdump capabilities:\n  sudo setcap cap_net_raw,cap_net_admin=eip " + tcpdumpBin
}
