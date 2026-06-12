//go:build linux

package doctor

import (
	"fmt"
	"io"

	"github.com/sandialabs/abox/internal/backend"
)

// printTrafficFilterStatus prints the platform-specific traffic filter status.
// On Linux the packet filter is libvirt nwfilter.
func printTrafficFilterStatus(w io.Writer, be backend.Backend, name string) {
	names := be.ResourceNames(name)
	if ti := be.TrafficInterceptor(); ti != nil && ti.FilterExists(names.Filter) {
		fmt.Fprintf(w, "  nwfilter: defined (%s)\n", names.Filter)
	} else {
		fmt.Fprintln(w, "  nwfilter: not defined")
	}
}

// trafficFilterRulesHint is the platform-specific hint for traffic filter issues.
const trafficFilterRulesHint = "check nwfilter rules"
