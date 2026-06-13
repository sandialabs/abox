//go:build darwin

package doctor

import (
	"fmt"
	"io"

	"github.com/sandialabs/abox/internal/backend"
)

// printTrafficFilterStatus prints the platform-specific traffic filter status.
// On macOS the packet filter is pf, not libvirt nwfilter.
func printTrafficFilterStatus(w io.Writer, be backend.Backend, name string) {
	names := be.ResourceNames(name)
	if ti := be.TrafficInterceptor(); ti != nil && ti.FilterExists(names.Filter) {
		fmt.Fprintf(w, "  pf anchor: active (%s)\n", names.Filter)
	} else {
		fmt.Fprintln(w, "  pf anchor: not active")
	}
}

// trafficFilterRulesHint is the platform-specific hint for traffic filter issues.
const trafficFilterRulesHint = "check pf anchor rules"
