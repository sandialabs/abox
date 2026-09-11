package filterbase

import (
	"fmt"
	"io"
	"strings"
)

// FilterDNS and FilterHTTP are the canonical filter names used for status
// display and warning/label matching. Callers should use these constants rather
// than bare string literals so a rename can't silently break the matching.
const (
	FilterDNS  = "DNS"
	FilterHTTP = "HTTP"
)

// StatusData contains the status information to display.
type StatusData struct {
	FilterName string // "DNS" or "HTTP"
	Mode       string
	Port       int32
	Domains    int32
	Total      uint64
	Allowed    uint64
	Blocked    uint64
	Uptime     string
	MITM       bool // HTTP only: TLS MITM interception enabled
}

// ModePassive is the mode string reported when a filter is in learning/passive
// mode (all traffic allowed, no filtering). Mirrors allowlist.ModePassive without
// importing it (allowlist depends on filterbase).
const ModePassive = "passive"

// DisplayStatus prints the filter status in a consistent format.
func DisplayStatus(w io.Writer, d StatusData) {
	fmt.Fprintf(w, "%s Filter Status\n", d.FilterName)
	fmt.Fprintln(w, strings.Repeat("=", 40))
	fmt.Fprintf(w, "Mode:            %s\n", d.Mode)
	if d.FilterName == FilterHTTP {
		if d.MITM {
			fmt.Fprintln(w, "MITM:            enabled")
		} else {
			fmt.Fprintln(w, "MITM:            disabled")
		}
	}
	fmt.Fprintf(w, "Port:            %d\n", d.Port)
	fmt.Fprintf(w, "Domains:         %d\n", d.Domains)
	fmt.Fprintf(w, "Total %s:  %d\n", activityLabel(d.FilterName), d.Total)
	fmt.Fprintf(w, "Allowed:         %d\n", d.Allowed)
	fmt.Fprintf(w, "Blocked:         %d\n", d.Blocked)
	fmt.Fprintf(w, "Uptime:          %s\n", d.Uptime)

	// Surface degraded security states prominently — they silently weaken the
	// core guarantee and are easy to set.
	for _, warn := range d.SecurityWarnings() {
		fmt.Fprintf(w, "WARNING:         %s\n", warn)
	}
}

// SecurityWarnings returns human-readable warnings for degraded security states:
// passive mode (no filtering) and, for HTTP, disabled TLS MITM (HTTPS not
// inspected). It returns nil when the filter is in its secure default posture, so
// callers can treat a non-empty result as "attention needed".
func (d StatusData) SecurityWarnings() []string {
	var warns []string
	if d.Mode == ModePassive {
		warns = append(warns, d.FilterName+" filter is in PASSIVE mode — all traffic is allowed (no filtering)")
	}
	if d.FilterName == FilterHTTP && !d.MITM {
		warns = append(warns, "TLS MITM is disabled — HTTPS is not inspected (domain fronting and path-level exfiltration possible)")
	}
	return warns
}

// StatusJSON is the JSON representation of a filter status.
type StatusJSON struct {
	Filter  string `json:"filter"`
	Running bool   `json:"running"`
	Mode    string `json:"mode,omitempty"`
	Port    int32  `json:"port,omitempty"`
	Domains int32  `json:"domains,omitempty"`
	Total   uint64 `json:"total,omitempty"`
	Allowed uint64 `json:"allowed,omitempty"`
	Blocked uint64 `json:"blocked,omitempty"`
	Uptime  string `json:"uptime,omitempty"`
	MITM    *bool  `json:"mitm,omitempty"`
	// Warnings mirrors SecurityWarnings() so automated consumers of --json see the
	// same degraded-security signal (passive mode / MITM off) as the text output.
	Warnings []string `json:"warnings,omitempty"`
}

// ToJSON converts StatusData to its JSON representation.
func (d StatusData) ToJSON() StatusJSON {
	j := StatusJSON{
		Filter:   d.FilterName,
		Running:  true,
		Mode:     d.Mode,
		Port:     d.Port,
		Domains:  d.Domains,
		Total:    d.Total,
		Allowed:  d.Allowed,
		Blocked:  d.Blocked,
		Uptime:   d.Uptime,
		Warnings: d.SecurityWarnings(),
	}
	if d.FilterName == FilterHTTP {
		j.MITM = &d.MITM
	}
	return j
}

// activityLabel returns the appropriate label for the activity counter.
func activityLabel(filterName string) string {
	switch filterName {
	case FilterDNS:
		return "queries "
	case FilterHTTP:
		return "requests"
	default:
		return "requests"
	}
}
