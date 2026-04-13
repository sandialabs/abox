package filterbase

import (
	"fmt"
	"io"
	"strings"
)

// FilterHTTP is the filter name for HTTP filter status display.
const FilterHTTP = "HTTP"

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
}

// ToJSON converts StatusData to its JSON representation.
func (d StatusData) ToJSON() StatusJSON {
	j := StatusJSON{
		Filter:  d.FilterName,
		Running: true,
		Mode:    d.Mode,
		Port:    d.Port,
		Domains: d.Domains,
		Total:   d.Total,
		Allowed: d.Allowed,
		Blocked: d.Blocked,
		Uptime:  d.Uptime,
	}
	if d.FilterName == FilterHTTP {
		j.MITM = &d.MITM
	}
	return j
}

// activityLabel returns the appropriate label for the activity counter.
func activityLabel(filterName string) string {
	switch filterName {
	case "DNS":
		return "queries "
	case FilterHTTP:
		return "requests"
	default:
		return "requests"
	}
}
