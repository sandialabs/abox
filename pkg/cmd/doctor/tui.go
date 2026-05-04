package doctor

import (
	"fmt"
	"strings"
	"sync"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/dnsfilter"
	"github.com/sandialabs/abox/internal/httpfilter"
	"github.com/sandialabs/abox/internal/instance"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// tuiModel is the Bubbletea model for the doctor TUI.
type tuiModel struct {
	instanceName string
	diagramState *DiagramState
	results      []CheckResult
	phase        int
	done         bool
	err          error

	// Loaded instance data (set once in phase 1)
	inst      *config.Instance
	paths     *config.Paths
	vmIP      string
	vmRunning bool
	sshWorks  bool

	// For tracking filter results
	dnsResult  CheckResult
	httpResult CheckResult

	// Security info for display
	securityMode   string
	nwfilterExists bool
}

// phase1ResultMsg contains all results from phase 1.
type phase1ResultMsg struct {
	inst      *config.Instance
	paths     *config.Paths
	vmIP      string
	vmRunning bool
	results   []CheckResult
	err       error
}

// phase2ResultMsg contains all results from phase 2.
type phase2ResultMsg struct {
	dnsResult    CheckResult
	httpResult   CheckResult
	dnsUpstream  CheckResult
	httpUpstream CheckResult
	// Include data needed for phase 3
	inst      *config.Instance
	paths     *config.Paths
	vmIP      string
	vmRunning bool
}

// phase3ResultMsg contains all results from phase 3.
type phase3ResultMsg struct {
	sshResult CheckResult
	sshWorks  bool
	// Pass through from phase 2 for phase 4
	dnsResult  CheckResult
	httpResult CheckResult
	inst       *config.Instance
	paths      *config.Paths
	vmIP       string
}

// phase4ResultMsg contains all results from phase 4.
type phase4ResultMsg struct {
	results        []CheckResult
	securityMode   string
	nwfilterExists bool
}

// newTuiModel creates a new TUI model.
func newTuiModel(instanceName string) tuiModel {
	return tuiModel{
		instanceName: instanceName,
		diagramState: NewDiagramState(),
		results:      []CheckResult{},
		phase:        0,
	}
}

// Init starts the first phase of checks.
func (m tuiModel) Init() tea.Cmd {
	return m.runPhase1()
}

// Update handles messages and updates the model.
func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		if m.done {
			return m, tea.Quit
		}
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		}

	case phase1ResultMsg:
		if msg.err != nil {
			m.err = msg.err
			m.done = true
			return m, tea.Quit
		}
		m.inst = msg.inst
		m.paths = msg.paths
		m.vmIP = msg.vmIP
		m.vmRunning = msg.vmRunning
		m.results = append(m.results, msg.results...)
		for _, r := range msg.results {
			m.updateDiagramStateByName(r.Name, r)
		}
		m.phase = 2
		// Pass data through the message, not the model
		return m, runPhase2Cmd(m.instanceName, msg.inst, msg.paths, msg.vmIP, msg.vmRunning)

	case phase2ResultMsg:
		m.dnsResult = msg.dnsResult
		m.httpResult = msg.httpResult
		m.results = append(m.results, msg.dnsResult, msg.httpResult, msg.dnsUpstream, msg.httpUpstream)
		m.updateDiagramStateByID(CheckDNSFilter, msg.dnsResult)
		m.updateDiagramStateByID(CheckHTTPFilter, msg.httpResult)
		m.updateDiagramStateByID(CheckDNSUpstream, msg.dnsUpstream)
		m.updateDiagramStateByID(CheckHTTPUpstream, msg.httpUpstream)
		m.phase = 3
		// Pass data through the message, including dnsResult/httpResult for phase 4
		return m, runPhase3Cmd(msg.inst, msg.paths, msg.vmIP, msg.vmRunning, msg.dnsResult, msg.httpResult)

	case phase3ResultMsg:
		m.sshWorks = msg.sshWorks
		m.dnsResult = msg.dnsResult
		m.httpResult = msg.httpResult
		m.results = append(m.results, msg.sshResult)
		m.updateDiagramStateByID(CheckSSH, msg.sshResult)
		m.phase = 4
		// Pass data through the message
		return m, runPhase4Cmd(m.instanceName, msg.inst, msg.paths, msg.vmIP, msg.sshWorks, msg.dnsResult, msg.httpResult)

	case phase4ResultMsg:
		m.results = append(m.results, msg.results...)
		for _, r := range msg.results {
			m.updateDiagramStateByName(r.Name, r)
		}
		m.securityMode = msg.securityMode
		m.nwfilterExists = msg.nwfilterExists
		m.done = true
		return m, nil
	}

	return m, nil
}

// View renders the current state.
func (m tuiModel) View() tea.View {
	var sb strings.Builder

	// Render the diagram with security mode
	secMode := m.securityMode
	if secMode == "" {
		secMode = "..."
	}
	sb.WriteString(RenderDiagram(m.diagramState, m.instanceName, secMode))
	sb.WriteString("\n")

	// Show current phase
	phases := []string{"", "Host Checks", "Filter Services", "VM Connectivity", "In-VM Network"}
	if m.phase > 0 && m.phase < len(phases) {
		fmt.Fprintf(&sb, "Running: %s...\n", phases[m.phase])
	}

	// Show any errors
	if m.err != nil {
		errorStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
		sb.WriteString(errorStyle.Render(fmt.Sprintf("\nError: %v\n", m.err)))
	}

	// Show summary when done
	if m.done && m.err == nil {
		sb.WriteString(m.renderSummary())
	}

	if m.done {
		sb.WriteString("\nPress any key to exit\n")
	} else {
		sb.WriteString("\nPress q to quit\n")
	}

	v := tea.NewView(sb.String())
	v.AltScreen = true
	return v
}

func (m *tuiModel) updateDiagramStateByID(checkID CheckID, result CheckResult) {
	status := StatusOK
	if result.Skipped {
		status = StatusSkip
	} else if !result.Passed {
		status = StatusFail
	}

	switch checkID {
	case CheckConfig:
		m.diagramState.Config = status
	case CheckVM:
		m.diagramState.VM = status
	case CheckBridge:
		m.diagramState.Bridge = status
	case CheckVMIP:
		// VM IP is not displayed in diagram, but tracked for flow control
	case CheckHostDisk:
		m.diagramState.DiskSpace = status
	case CheckDNSFilter:
		m.diagramState.DNSFilter = status
	case CheckHTTPFilter:
		m.diagramState.HTTPFilter = status
	case CheckDNSUpstream:
		m.diagramState.DNSUpstream = status
	case CheckSSH:
		m.diagramState.SSHConn = status
	case CheckGateway:
		m.diagramState.Gateway = status
	case CheckDNSResolve:
		m.diagramState.DNSResolve = status
	case CheckHTTPProxy:
		m.diagramState.HTTPProxy = status
	case CheckGuestDisk:
		m.diagramState.GuestDisk = status
	case CheckProxyEnv:
		m.diagramState.ProxyEnv = status
	case CheckDNSConfig:
		m.diagramState.DNSConfig = status
	case CheckHTTPUpstream:
		m.diagramState.HTTPUpstream = status
	}
}

func (m *tuiModel) updateDiagramStateByName(name string, result CheckResult) {
	if checkID, ok := CheckIDFromName(name); ok {
		m.updateDiagramStateByID(checkID, result)
	}
}

func (m tuiModel) renderSummary() string {
	passed, failed, skipped := CountResults(m.results)

	okStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	failStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("9"))

	if failed == 0 {
		return okStyle.Render("All checks passed.")
	}

	var sb strings.Builder
	sb.WriteString(failStyle.Render(fmt.Sprintf("%d check(s) failed", failed)))
	fmt.Fprintf(&sb, ", %d passed", passed)
	if skipped > 0 {
		fmt.Fprintf(&sb, ", %d skipped", skipped)
	}
	sb.WriteString(".\n\n")

	// Show failed checks with hints
	sb.WriteString("Failed checks:\n")
	for _, r := range m.results {
		if !r.Skipped && !r.Passed {
			fmt.Fprintf(&sb, "  - %s", r.Name)
			if r.Details != "" {
				fmt.Fprintf(&sb, ": %s", r.Details)
			}
			sb.WriteString("\n")
			if r.Hint != "" {
				fmt.Fprintf(&sb, "    Hint: %s\n", r.Hint)
			}
		}
	}

	return sb.String()
}

// Phase 1: Host Checks
func (m tuiModel) runPhase1() tea.Cmd {
	instanceName := m.instanceName
	return func() tea.Msg {
		var results []CheckResult

		// Check 1: Instance configuration
		inst, paths, err := instance.LoadRequired(instanceName)
		result := CheckResult{Name: CheckNameConfig}
		if err != nil {
			result.Passed = false
			result.Details = err.Error()
			result.Hint = "Check that the instance exists with 'abox list'"
			results = append(results, result)
			return phase1ResultMsg{err: fmt.Errorf("instance %q not found", instanceName), results: results}
		}
		result.Passed = true
		results = append(results, result)

		// Get the backend for this instance
		be, err := backend.ForInstance(inst)
		if err != nil {
			// Fall back to auto-detect
			be, err = backend.AutoDetect()
			if err != nil {
				results = append(results, CheckResult{
					Name:    "Backend available",
					Passed:  false,
					Details: err.Error(),
					Hint:    "Ensure a supported virtualization backend is available",
				})
				return phase1ResultMsg{err: err, results: results}
			}
		}

		// Check 2: VM running
		state := be.VM().State(instanceName)
		vmResult := CheckResult{Name: CheckNameVMRunning}
		vmRunning := false
		if state == backend.VMStateRunning {
			vmResult.Passed = true
			vmResult.Details = fmt.Sprintf("state: %s", state)
			vmRunning = true
		} else {
			vmResult.Passed = false
			vmResult.Details = fmt.Sprintf("state: %s", state)
			vmResult.Hint = fmt.Sprintf("Start the instance with 'abox start %s'", instanceName)
		}
		results = append(results, vmResult)

		// Check 3: Network bridge
		networkActive := be.Network().IsActive(inst.Bridge)
		bridgeResult := CheckResult{Name: CheckNameBridge}
		if networkActive {
			bridgeResult.Passed = true
			bridgeResult.Details = inst.Bridge
		} else {
			bridgeResult.Passed = false
			bridgeResult.Details = fmt.Sprintf("bridge %s is inactive", inst.Bridge)
			bridgeResult.Hint = fmt.Sprintf("Try 'abox start %s' to recreate the network", instanceName)
		}
		results = append(results, bridgeResult)

		// Check 4: VM IP
		ipResult := CheckResult{Name: CheckNameVMIP}
		var vmIP string
		if vmRunning {
			ip, err := instance.GetIP(inst, be.VM())
			if err != nil {
				ipResult.Passed = false
				ipResult.Details = err.Error()
				ipResult.Hint = "VM may still be booting"
			} else {
				ipResult.Passed = true
				ipResult.Details = ip
				vmIP = ip
			}
		} else {
			ipResult.Skipped = true
		}
		results = append(results, ipResult)

		// Check 5: Host disk space
		results = append(results, checkHostDiskSpace(paths))

		return phase1ResultMsg{
			inst:      inst,
			paths:     paths,
			vmIP:      vmIP,
			vmRunning: vmRunning,
			results:   results,
		}
	}
}

// runPhase2Cmd returns a command that runs phase 2 checks.
// Data is passed explicitly to avoid stale model state in closures.
func runPhase2Cmd(instanceName string, inst *config.Instance, paths *config.Paths, vmIP string, vmRunning bool) tea.Cmd {
	return func() tea.Msg {
		var wg sync.WaitGroup
		var dnsResult, httpResult CheckResult
		wg.Add(2)

		go func() {
			defer wg.Done()
			dnsResult = checkDNSFilter(instanceName, paths, inst.DNS.Port)
		}()

		go func() {
			defer wg.Done()
			httpResult = checkHTTPFilter(instanceName, paths, inst.HTTP.Port)
		}()

		wg.Wait()

		dnsUpstream := checkDNSUpstream(inst)
		httpUpstream := checkHTTPUpstream()

		return phase2ResultMsg{
			dnsResult:    dnsResult,
			httpResult:   httpResult,
			dnsUpstream:  dnsUpstream,
			httpUpstream: httpUpstream,
			inst:         inst,
			paths:        paths,
			vmIP:         vmIP,
			vmRunning:    vmRunning,
		}
	}
}

// runPhase3Cmd returns a command that runs phase 3 checks.
func runPhase3Cmd(inst *config.Instance, paths *config.Paths, vmIP string, vmRunning bool, dnsResult, httpResult CheckResult) tea.Cmd {
	return func() tea.Msg {
		result := CheckResult{Name: CheckNameSSH}
		sshWorks := false
		if vmRunning && vmIP != "" {
			if testSSH(paths, inst.GetUser(), vmIP) {
				result.Passed = true
				sshWorks = true
			} else {
				result.Passed = false
				result.Details = "connection failed"
				result.Hint = "VM may still be booting"
			}
		} else {
			result.Skipped = true
		}

		return phase3ResultMsg{
			sshResult:  result,
			sshWorks:   sshWorks,
			dnsResult:  dnsResult,
			httpResult: httpResult,
			inst:       inst,
			paths:      paths,
			vmIP:       vmIP,
		}
	}
}

// checkInVMGateway checks whether the VM can reach its gateway.
func checkInVMGateway(paths *config.Paths, inst *config.Instance, vmIP string, sshWorks bool) CheckResult {
	result := CheckResult{Name: CheckNameGateway}
	if !sshWorks {
		result.Skipped = true
		return result
	}
	if testGatewayPing(paths, inst.GetUser(), vmIP, inst.Gateway) {
		result.Passed = true
		result.Details = inst.Gateway
		return result
	}
	result.Details = "cannot reach gateway " + inst.Gateway
	result.Hint = "Check network configuration"
	return result
}

// checkInVMDNSResolve checks DNS resolution from inside the VM.
func checkInVMDNSResolve(paths *config.Paths, inst *config.Instance, vmIP string, sshWorks bool, dnsResult CheckResult) CheckResult {
	result := CheckResult{Name: CheckNameDNSResolve}
	if !sshWorks || !dnsResult.Passed {
		result.Skipped = true
		return result
	}
	if testDNSResolution(paths, inst.GetUser(), vmIP, inst.Gateway) {
		result.Passed = true
		return result
	}
	result.Details = fmt.Sprintf("DNS query to %s failed", dnsfilter.HealthcheckDomain)
	result.Hint = "Check dnsfilter or iptables NAT rules"
	return result
}

// checkInVMHTTPProxy checks HTTP proxy reachability from inside the VM.
func checkInVMHTTPProxy(paths *config.Paths, inst *config.Instance, vmIP string, sshWorks bool, httpResult CheckResult) CheckResult {
	result := CheckResult{Name: CheckNameHTTPProxy}
	if !sshWorks || !httpResult.Passed {
		result.Skipped = true
		return result
	}
	if testHTTPProxy(paths, inst.GetUser(), vmIP, inst.Gateway, inst.HTTP.Port) {
		result.Passed = true
		return result
	}
	result.Details = fmt.Sprintf("HTTP request to %s failed", httpfilter.HealthcheckDomain)
	result.Hint = "Check httpfilter configuration"
	return result
}

// skipOrRun returns the check result, or a skipped result if sshWorks is false.
func skipOrRun(name string, sshWorks bool, fn func() CheckResult) CheckResult {
	if !sshWorks {
		return CheckResult{Name: name, Skipped: true}
	}
	return fn()
}

// checkNWFilterExists checks whether the nwfilter resource exists for the instance.
func checkNWFilterExists(instanceName string, inst *config.Instance) bool {
	be, err := backend.ForInstance(inst)
	if err != nil {
		be, _ = backend.AutoDetect()
	}
	if be == nil {
		return false
	}
	names := be.ResourceNames(instanceName)
	if ti := be.TrafficInterceptor(); ti != nil {
		return ti.FilterExists(names.Filter)
	}
	return false
}

// runPhase4Cmd returns a command that runs phase 4 checks.
func runPhase4Cmd(instanceName string, inst *config.Instance, paths *config.Paths, vmIP string, sshWorks bool, dnsResult, httpResult CheckResult) tea.Cmd {
	return func() tea.Msg {
		user := inst.GetUser()
		results := []CheckResult{
			checkInVMGateway(paths, inst, vmIP, sshWorks),
			checkInVMDNSResolve(paths, inst, vmIP, sshWorks, dnsResult),
			checkInVMHTTPProxy(paths, inst, vmIP, sshWorks, httpResult),
			skipOrRun(CheckNameGuestDisk, sshWorks, func() CheckResult {
				return checkGuestDiskSpace(paths, user, vmIP)
			}),
			skipOrRun(CheckNameProxyEnv, sshWorks, func() CheckResult {
				return checkProxyEnvVars(paths, user, vmIP, inst.Gateway, inst.HTTP.Port)
			}),
			skipOrRun(CheckNameDNSConfig, sshWorks, func() CheckResult {
				return checkDNSConfig(paths, user, vmIP, inst.Gateway)
			}),
		}

		return phase4ResultMsg{
			results:        results,
			securityMode:   "filtered",
			nwfilterExists: checkNWFilterExists(instanceName, inst),
		}
	}
}

// runDoctorTUI runs the doctor command with TUI.
func runDoctorTUI(name string) error {
	// Validate instance exists before showing TUI
	if _, _, err := instance.LoadRequired(name); err != nil {
		return err
	}

	p := tea.NewProgram(newTuiModel(name))
	finalModel, err := p.Run()
	if err != nil {
		return err
	}

	// Check if the TUI model had an error
	if m, ok := finalModel.(tuiModel); ok && m.err != nil {
		return m.err
	}

	return nil
}
