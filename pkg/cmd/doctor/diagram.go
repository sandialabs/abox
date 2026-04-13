package doctor

import (
	"strings"

	"charm.land/lipgloss/v2"
)

// DiagramStatus represents the status of a component in the diagram.
type DiagramStatus string

const (
	StatusPending DiagramStatus = " .. "
	StatusOK      DiagramStatus = " OK "
	StatusFail    DiagramStatus = "FAIL"
	StatusSkip    DiagramStatus = "SKIP"
)

// DiagramState holds the status of each component for the diagram.
type DiagramState struct {
	Config       DiagramStatus
	VM           DiagramStatus
	Bridge       DiagramStatus
	DiskSpace    DiagramStatus
	DNSFilter    DiagramStatus
	HTTPFilter   DiagramStatus
	DNSUpstream  DiagramStatus
	SSHConn      DiagramStatus
	Gateway      DiagramStatus
	DNSResolve   DiagramStatus
	HTTPProxy    DiagramStatus
	GuestDisk    DiagramStatus
	ProxyEnv     DiagramStatus
	DNSConfig    DiagramStatus
	HTTPUpstream DiagramStatus
}

// NewDiagramState creates a new diagram state with all pending.
func NewDiagramState() *DiagramState {
	return &DiagramState{
		Config:       StatusPending,
		VM:           StatusPending,
		Bridge:       StatusPending,
		DiskSpace:    StatusPending,
		DNSFilter:    StatusPending,
		HTTPFilter:   StatusPending,
		DNSUpstream:  StatusPending,
		SSHConn:      StatusPending,
		Gateway:      StatusPending,
		DNSResolve:   StatusPending,
		HTTPProxy:    StatusPending,
		GuestDisk:    StatusPending,
		ProxyEnv:     StatusPending,
		DNSConfig:    StatusPending,
		HTTPUpstream: StatusPending,
	}
}

// RenderDiagram renders the architecture diagram with current status.
func RenderDiagram(state *DiagramState, instanceName string, securityMode string) string {
	var sb strings.Builder

	// Define styles
	okStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10"))     // green
	failStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("9"))    // red
	pendingStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8")) // gray
	skipStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("11"))   // yellow
	boxStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("12"))    // blue
	headerStyle := lipgloss.NewStyle().Bold(true)

	statusStyle := func(s DiagramStatus) lipgloss.Style {
		switch s {
		case StatusOK:
			return okStyle
		case StatusFail:
			return failStyle
		case StatusSkip:
			return skipStyle
		case StatusPending:
			return pendingStyle
		default:
			return pendingStyle
		}
	}

	formatStatus := func(s DiagramStatus) string {
		style := statusStyle(s)
		return style.Render(string(s))
	}

	// box styles only the box characters in a string (|, +, -, ^, v)
	// For lines with mixed content, we need to be more careful
	box := func(s string) string {
		return boxStyle.Render(s)
	}

	// For mixed lines, style box chars and content separately
	// Use fixed-width formatting to maintain alignment
	pipe := boxStyle.Render("|")

	// Header
	sb.WriteString(headerStyle.Render("abox doctor: " + instanceName))
	sb.WriteString("\n\n")

	// Row 1: HOST and INTERNET
	sb.WriteString("    HOST                                          INTERNET\n")
	sb.WriteString(box("    +------------------+                      +--------------+") + "\n")
	sb.WriteString("    " + pipe + " Config   [" + formatStatus(state.Config) + "]  " + pipe + "                      " + pipe + " DNS  [" + formatStatus(state.DNSUpstream) + "] " + pipe + "\n")
	sb.WriteString("    " + pipe + " VM       [" + formatStatus(state.VM) + "]  " + pipe + "                      " + pipe + " HTTP [" + formatStatus(state.HTTPUpstream) + "] " + pipe + "\n")
	sb.WriteString("    " + pipe + " Bridge   [" + formatStatus(state.Bridge) + "]  " + pipe + "                      " + box("+--------------+") + "\n")
	sb.WriteString("    " + pipe + " Disk     [" + formatStatus(state.DiskSpace) + "]  " + pipe + "                             " + box("^") + "\n")
	sb.WriteString(box("    +------------------+                             |") + " " + securityMode + "\n")
	sb.WriteString(box("            |                                        |") + "\n")
	sb.WriteString(box("            v                                        |") + "\n")

	// Row 2: Virtual Network
	sb.WriteString(box("    +----------------------------------------------------+") + "\n")
	sb.WriteString(box("            |                 |                 |") + "\n")
	sb.WriteString(box("            v                 v                 v") + "\n")

	// Row 3: Filters and Guest
	sb.WriteString(box("    +--------------+  +--------------+  +--------------+") + "\n")
	sb.WriteString("    " + pipe + "  DNS Filter  " + pipe + "  " + pipe + " HTTP Filter  " + pipe + "  " + pipe + "    Guest     " + pipe + "\n")
	sb.WriteString("    " + pipe + "     [" + formatStatus(state.DNSFilter) + "]   " + pipe + "  " + pipe + "     [" + formatStatus(state.HTTPFilter) + "]   " + pipe + "  " + pipe + "     [" + formatStatus(state.SSHConn) + "]   " + pipe + "\n")
	sb.WriteString(box("    +--------------+  +--------------+  +--------------+") + "\n")
	sb.WriteString(box("            |                 |                 |") + "\n")
	sb.WriteString(box("            +--------+--------+-----------------+") + "\n")
	sb.WriteString(box("                     |") + "\n")

	// Row 4: In-VM Checks
	sb.WriteString(box("    +----------------------------------------------------+") + "\n")
	sb.WriteString(box("    |                    IN-VM CHECKS                    |") + "\n")
	sb.WriteString(box("    +----------------------------------------------------+") + "\n")
	sb.WriteString("    " + pipe + "  Gateway    [" + formatStatus(state.Gateway) + "]    DNS Resolve [" + formatStatus(state.DNSResolve) + "]           " + pipe + "\n")
	sb.WriteString("    " + pipe + "  HTTP Proxy [" + formatStatus(state.HTTPProxy) + "]    Proxy Env   [" + formatStatus(state.ProxyEnv) + "]           " + pipe + "\n")
	sb.WriteString("    " + pipe + "  DNS Config [" + formatStatus(state.DNSConfig) + "]    Guest Disk  [" + formatStatus(state.GuestDisk) + "]           " + pipe + "\n")
	sb.WriteString(box("    +----------------------------------------------------+") + "\n")

	return sb.String()
}
