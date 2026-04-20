// Package doctor provides the doctor command for diagnosing abox instance issues.
package doctor

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/dnsfilter"
	"github.com/sandialabs/abox/internal/httpfilter"
	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/sshutil"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// CheckResult holds the result of a single diagnostic check.
type CheckResult struct {
	Name    string
	Passed  bool
	Details string
	Hint    string
	Skipped bool
}

// minHostDiskSpaceBytes is the minimum recommended free disk space (1GB).
const minHostDiskSpaceBytes = 1024 * 1024 * 1024

// maxGuestDiskUsagePercent is the threshold for guest disk usage warnings.
const maxGuestDiskUsagePercent = 90

const hintCheckCloudInit = "Check cloud-init configuration"

// sshTimeoutOpts are the common SSH options for quick connectivity tests.
var sshTimeoutOpts = []string{"-o", "ConnectTimeout=5", "-o", "BatchMode=yes"}

// Options holds the options for the doctor command.
type Options struct {
	Factory *factory.Factory
	Plain   bool
	Name    string
}

// NewCmdDoctor creates a new doctor command.
func NewCmdDoctor(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:     "doctor <instance>",
		Aliases: []string{"troubleshoot"},
		Short:   "Run diagnostic checks on an abox instance",
		Long: `Run comprehensive diagnostic checks on an abox instance.

This command performs a series of checks to diagnose connectivity and
configuration issues:

  - Host checks: config, VM status, network bridge, IP address, disk space
  - Filter services: DNS filter, HTTP filter, and upstream connectivity
  - VM connectivity: SSH connection test
  - In-VM network: gateway, DNS resolution, HTTP proxy, guest config

By default, displays an interactive TUI with an architecture diagram.
Use --plain for plain text output (automatically enabled when stdout is not a TTY).

Uses the special healthcheck.abox.local domain which always responds
regardless of filter mode or allowlist configuration.`,
		Example: `  abox doctor dev                    # Interactive diagnostic TUI
  abox doctor dev --plain            # Plain text output`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completion.Sequence(completion.AllInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if runF != nil {
				return runF(opts)
			}
			// Use plain mode if explicitly requested or if stdout is not a TTY
			if opts.Plain || !f.IO.IsTerminal() {
				return runDoctor(f.IO.Out, args[0])
			}
			return runDoctorTUI(args[0])
		},
	}

	cmd.Flags().BoolVar(&opts.Plain, "plain", false, "Disable TUI, use plain text output")

	return cmd
}

func runDoctor(w io.Writer, name string) error {
	fmt.Fprintf(w, "Diagnosing instance: %s\n\n", name)

	var results []CheckResult
	var sshWorks bool

	// Phase 1: Host Checks
	fmt.Fprintln(w, "[Host Checks]")
	hostResults, inst, paths, be, vmIP, vmRunning := runHostChecks(w, name)
	results = append(results, hostResults...)

	if inst == nil {
		printSummary(w, results)
		return nil
	}

	// Phase 2: Filter Services (parallel)
	fmt.Fprintln(w, "\n[Filter Services]")

	var dnsResult, httpResult CheckResult
	var wg sync.WaitGroup
	wg.Add(2)

	// Check 6: DNS filter
	go func() {
		defer wg.Done()
		dnsResult = checkDNSFilter(name, paths, inst.DNS.Port)
	}()

	// Check 7: HTTP filter
	go func() {
		defer wg.Done()
		httpResult = checkHTTPFilter(name, paths, inst.HTTP.Port)
	}()

	wg.Wait()
	printResult(w, dnsResult)
	results = append(results, dnsResult)
	printResult(w, httpResult)
	results = append(results, httpResult)

	// Check: DNS upstream
	result := checkDNSUpstream(inst)
	printResult(w, result)
	results = append(results, result)

	// Check: HTTP upstream
	result = checkHTTPUpstream()
	printResult(w, result)
	results = append(results, result)

	// Phase 3: VM Connectivity
	fmt.Fprintln(w, "\n[VM Connectivity]")

	// Check 7: SSH connection
	result = CheckResult{Name: CheckNameSSH}
	if vmRunning && vmIP != "" {
		if testSSH(paths, inst.GetUser(), vmIP) {
			result.Passed = true
			sshWorks = true
		} else {
			result.Passed = false
			result.Details = "connection failed"
			result.Hint = "VM may still be booting, or SSH is not configured correctly"
		}
	} else {
		result.Skipped = true
	}
	printResult(w, result)
	results = append(results, result)

	// Phase 4: In-VM Network (requires SSH)
	fmt.Fprintln(w, "\n[In-VM Network]")
	results = append(results, runInVMChecks(w, paths, inst, vmIP, sshWorks, dnsResult, httpResult)...)

	// Phase 5: Security Status (informational)
	fmt.Fprintln(w, "\n[Security]")

	names := be.ResourceNames(name)
	if ti := be.TrafficInterceptor(); ti != nil && ti.FilterExists(names.Filter) {
		fmt.Fprintf(w, "  nwfilter: defined (%s)\n", names.Filter)
	} else {
		fmt.Fprintln(w, "  nwfilter: not defined")
	}

	printSummary(w, results)
	return nil
}

// runHostChecks runs Phase 1 host diagnostics: config, VM state, network, IP, disk.
// Returns nil inst/paths/be if the instance config check fails (caller should bail early).
func runHostChecks(w io.Writer, name string) (results []CheckResult, inst *config.Instance, paths *config.Paths, be backend.Backend, vmIP string, vmRunning bool) {
	// Check 1: Instance configuration
	var err error
	inst, paths, err = instance.LoadRequired(name)
	result := CheckResult{Name: CheckNameConfig, Passed: err == nil}
	if err != nil {
		result.Details = err.Error()
		result.Hint = "Check that the instance exists with 'abox list'"
	}
	printResult(w, result)
	results = append(results, result)

	if !result.Passed {
		return results, nil, nil, nil, "", false
	}

	// Get the backend for this instance
	be, err = backend.ForInstance(inst)
	if err != nil {
		be, err = backend.AutoDetect()
		if err != nil {
			result = CheckResult{Name: "Backend detection", Details: err.Error()}
			printResult(w, result)
			results = append(results, result)
			return results, nil, nil, nil, "", false
		}
	}

	// Check 2: VM running
	state := be.VM().State(name)
	result = CheckResult{
		Name:    CheckNameVMRunning,
		Passed:  state == backend.VMStateRunning,
		Details: fmt.Sprintf("state: %s", state),
	}
	if result.Passed {
		vmRunning = true
	} else {
		result.Hint = fmt.Sprintf("Start the instance with 'abox start %s'", name)
	}
	printResult(w, result)
	results = append(results, result)

	// Check 3: Network bridge active
	networkActive := be.Network().IsActive(inst.Bridge)
	result = CheckResult{Name: CheckNameBridge, Passed: networkActive}
	if networkActive {
		result.Details = inst.Bridge
	} else {
		result.Details = fmt.Sprintf("bridge %s is inactive", inst.Bridge)
		result.Hint = fmt.Sprintf("Try 'abox start %s' to recreate the network", name)
	}
	printResult(w, result)
	results = append(results, result)

	// Check 4: VM IP address
	result = CheckResult{Name: CheckNameVMIP}
	if !vmRunning {
		result.Skipped = true
	} else {
		vmIP, err = be.VM().GetIP(name)
		result.Passed = err == nil
		if err != nil {
			result.Details = err.Error()
			result.Hint = "VM may still be booting, wait a moment and retry"
		} else {
			result.Details = vmIP
		}
	}
	printResult(w, result)
	results = append(results, result)

	// Check 5: Host disk space
	result = checkHostDiskSpace(paths)
	printResult(w, result)
	results = append(results, result)

	return results, inst, paths, be, vmIP, vmRunning
}

func runInVMChecks(w io.Writer, paths *config.Paths, inst *config.Instance, vmIP string, sshWorks bool, dnsResult, httpResult CheckResult) []CheckResult {
	var results []CheckResult

	// Gateway ping
	result := CheckResult{Name: CheckNameGateway}
	switch {
	case !sshWorks:
		result.Skipped = true
	case testGatewayPing(paths, inst.GetUser(), vmIP, inst.Gateway):
		result.Passed = true
		result.Details = inst.Gateway
	default:
		result.Details = "cannot reach gateway " + inst.Gateway
		result.Hint = "Check network configuration and nwfilter rules"
	}
	printResult(w, result)
	results = append(results, result)

	// DNS resolution
	result = checkInVMDNS(paths, inst, vmIP, sshWorks, dnsResult)
	printResult(w, result)
	results = append(results, result)

	// HTTP proxy
	result = checkInVMHTTP(paths, inst, vmIP, sshWorks, httpResult)
	printResult(w, result)
	results = append(results, result)

	// Remaining SSH-gated checks
	for _, check := range []struct {
		name string
		fn   func() CheckResult
	}{
		{CheckNameGuestDisk, func() CheckResult { return checkGuestDiskSpace(paths, inst.GetUser(), vmIP) }},
		{CheckNameProxyEnv, func() CheckResult {
			return checkProxyEnvVars(paths, inst.GetUser(), vmIP, inst.Gateway, inst.HTTP.Port)
		}},
		{CheckNameDNSConfig, func() CheckResult { return checkDNSConfig(paths, inst.GetUser(), vmIP, inst.Gateway) }},
	} {
		result = CheckResult{Name: check.name}
		if sshWorks {
			result = check.fn()
		} else {
			result.Skipped = true
		}
		printResult(w, result)
		results = append(results, result)
	}

	return results
}

func checkInVMDNS(paths *config.Paths, inst *config.Instance, vmIP string, sshWorks bool, dnsResult CheckResult) CheckResult {
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
	if testTCPConnect(paths, inst.GetUser(), vmIP, inst.Gateway, 53) {
		result.Hint = "TCP connection to DNS port 53 works but dig query failed - check dnsfilter or iptables NAT rules"
	} else {
		result.Hint = "Cannot establish TCP connection to gateway:53 - check nwfilter rules"
	}
	return result
}

func checkInVMHTTP(paths *config.Paths, inst *config.Instance, vmIP string, sshWorks bool, httpResult CheckResult) CheckResult {
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
	if testTCPConnect(paths, inst.GetUser(), vmIP, inst.Gateway, inst.HTTP.Port) {
		result.Hint = "TCP connection to HTTP proxy works but proxy not responding correctly - check httpfilter configuration"
	} else {
		result.Hint = fmt.Sprintf("Cannot establish TCP connection to gateway:%d - check nwfilter rules", inst.HTTP.Port)
	}
	return result
}

func printResult(w io.Writer, r CheckResult) {
	if r.Skipped {
		fmt.Fprintf(w, "  - %s (skipped)\n", r.Name)
		return
	}

	if r.Passed {
		if r.Details != "" {
			fmt.Fprintf(w, "  \u2713 %s (%s)\n", r.Name, r.Details)
		} else {
			fmt.Fprintf(w, "  \u2713 %s\n", r.Name)
		}
		return
	}

	fmt.Fprintf(w, "  \u2717 %s\n", r.Name)
	if r.Details != "" {
		fmt.Fprintf(w, "      %s\n", r.Details)
	}
	if r.Hint != "" {
		fmt.Fprintf(w, "      Hint: %s\n", r.Hint)
	}
}

func printSummary(w io.Writer, results []CheckResult) {
	fmt.Fprintln(w)

	passed, failed, skipped := CountResults(results)

	if failed == 0 {
		fmt.Fprintln(w, "All checks passed.")
	} else {
		fmt.Fprintf(w, "%d check(s) failed, %d passed", failed, passed)
		if skipped > 0 {
			fmt.Fprintf(w, ", %d skipped", skipped)
		}
		fmt.Fprintln(w, ".")
	}
}

// checkDNSFilter checks the DNS filter using the generic checker.
func checkDNSFilter(name string, paths *config.Paths, port int) CheckResult {
	return checkDNSFilterGeneric(name, paths, port)
}

// checkHTTPFilter checks the HTTP filter using the generic checker.
func checkHTTPFilter(name string, paths *config.Paths, port int) CheckResult {
	return checkHTTPFilterGeneric(name, paths, port)
}

// buildSSHArgs builds SSH args with timeout options prepended.
func buildSSHArgs(paths *config.Paths, user, ip string, command ...string) []string {
	// Copy sshTimeoutOpts to avoid modifying the package-level slice
	args := make([]string, len(sshTimeoutOpts), len(sshTimeoutOpts)+10)
	copy(args, sshTimeoutOpts)
	return append(args, sshutil.BuildSSHArgs(paths, user, ip, command...)...)
}

// runSSHCommand runs a command on the VM via SSH and returns whether it succeeded.
func runSSHCommand(paths *config.Paths, user, ip string, command ...string) bool {
	return exec.Command("ssh", buildSSHArgs(paths, user, ip, command...)...).Run() == nil
}

// runSSHCommandOutput runs a command on the VM via SSH and returns the output.
func runSSHCommandOutput(paths *config.Paths, user, ip string, command ...string) ([]byte, error) {
	return exec.Command("ssh", buildSSHArgs(paths, user, ip, command...)...).Output()
}

func testSSH(paths *config.Paths, user, ip string) bool {
	return runSSHCommand(paths, user, ip, "true")
}

func testGatewayPing(paths *config.Paths, user, ip, gateway string) bool {
	return runSSHCommand(paths, user, ip, "ping", "-c", "1", "-W", "2", gateway)
}

// testTCPConnect tests raw TCP connectivity to a host:port using nc (netcat).
// This helps distinguish between network-level issues (can't TCP connect) and
// application-level issues (TCP works but service not responding correctly).
func testTCPConnect(paths *config.Paths, user, ip, host string, port int) bool {
	portStr := strconv.Itoa(port)
	return runSSHCommand(paths, user, ip, "nc", "-z", "-w", "2", host, portStr)
}

func testDNSResolution(paths *config.Paths, user, ip, gateway string) bool {
	// Test port 53, which is what the VM actually uses. Iptables PREROUTING
	// redirects port 53 to the actual dnsfilter port.
	output, err := runSSHCommandOutput(paths, user, ip,
		"dig", "@"+gateway, dnsfilter.HealthcheckDomain, "+short", "+time=2", "+tries=1")
	if err != nil {
		return false
	}
	// dig +short returns "127.0.0.1\n" for our healthcheck domain
	return strings.TrimSpace(string(output)) == "127.0.0.1"
}

func testHTTPProxy(paths *config.Paths, user, ip, gateway string, httpPort int) bool {
	proxyURL := "http://" + net.JoinHostPort(gateway, strconv.Itoa(httpPort))
	targetURL := fmt.Sprintf("http://%s/", httpfilter.HealthcheckDomain)
	output, err := runSSHCommandOutput(paths, user, ip,
		"curl", "--proxy", proxyURL, targetURL, "--max-time", "5", "-s")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "abox healthcheck OK"
}

// checkHostDiskSpace checks if there's enough disk space in the abox data directory.
func checkHostDiskSpace(paths *config.Paths) CheckResult {
	result := CheckResult{Name: CheckNameHostDisk}

	// Check the instances directory which is under ~/.local/share/abox/
	dataDir := paths.Instances
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dataDir, &stat); err != nil {
		result.Passed = false
		result.Details = fmt.Sprintf("failed to check disk space: %v", err)
		return result
	}

	availableBytes := stat.Bavail * uint64(stat.Bsize) //nolint:gosec // Bsize is always positive on Linux
	availableMB := availableBytes / (1024 * 1024)

	if availableBytes < minHostDiskSpaceBytes {
		result.Passed = false
		result.Details = fmt.Sprintf("%d MB available in %s", availableMB, dataDir)
		result.Hint = "Free up disk space to prevent VM issues"
		return result
	}

	result.Passed = true
	result.Details = fmt.Sprintf("%d MB available", availableMB)
	return result
}

// checkGuestDiskSpace checks if the guest has sufficient disk space.
func checkGuestDiskSpace(paths *config.Paths, user, ip string) CheckResult {
	result := CheckResult{Name: CheckNameGuestDisk}

	output, err := runSSHCommandOutput(paths, user, ip, "df", "-h", "/")
	if err != nil {
		result.Passed = false
		result.Details = "failed to check disk space"
		return result
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		result.Passed = false
		result.Details = "unexpected df output"
		return result
	}

	// Parse the df output to get use percentage
	fields := strings.Fields(lines[1])
	if len(fields) < 5 {
		result.Passed = false
		result.Details = "unexpected df output format"
		return result
	}

	usePercent := strings.TrimSuffix(fields[4], "%")
	var pct int
	if _, err := fmt.Sscanf(usePercent, "%d", &pct); err != nil {
		result.Passed = false
		result.Details = "failed to parse usage percentage"
		return result
	}

	if pct >= maxGuestDiskUsagePercent {
		result.Passed = false
		result.Details = fmt.Sprintf("%d%% used", pct)
		result.Hint = "Guest disk is nearly full"
		return result
	}

	result.Passed = true
	result.Details = fmt.Sprintf("%d%% used", pct)
	return result
}

// checkDNSUpstream tests if the upstream DNS server is reachable from the host.
func checkDNSUpstream(inst *config.Instance) CheckResult {
	result := CheckResult{Name: CheckNameDNSUpstream}

	upstream := inst.DNS.Upstream
	if upstream == "" {
		upstream = "8.8.8.8:53"
	}

	// Use dig to test upstream DNS
	cmd := exec.Command("dig", "@"+strings.Split(upstream, ":")[0], "google.com", "+short", "+time=2", "+tries=1")
	output, err := cmd.Output()
	if err != nil {
		result.Passed = false
		result.Details = "failed to reach " + upstream
		result.Hint = "Check host network connectivity and DNS configuration"
		return result
	}

	if strings.TrimSpace(string(output)) == "" {
		result.Passed = false
		result.Details = "empty response from upstream"
		result.Hint = "Upstream DNS may be blocked or misconfigured"
		return result
	}

	result.Passed = true
	result.Details = upstream
	return result
}

// checkHTTPUpstream tests if the host can reach external HTTPS endpoints.
func checkHTTPUpstream() CheckResult {
	result := CheckResult{Name: CheckNameHTTPUpstream}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://www.google.com/robots.txt") //nolint:noctx // diagnostic check with timeout
	if err != nil {
		result.Passed = false
		result.Details = "failed to reach external HTTPS"
		result.Hint = "Check host network connectivity"
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		result.Passed = false
		result.Details = fmt.Sprintf("HTTP status %d", resp.StatusCode)
		result.Hint = "Check host network connectivity"
		return result
	}

	result.Passed = true
	return result
}

// checkProxyEnvVars verifies HTTP_PROXY and HTTPS_PROXY are set in the guest.
func checkProxyEnvVars(paths *config.Paths, user, ip, gateway string, httpPort int) CheckResult {
	result := CheckResult{Name: CheckNameProxyEnv}

	expectedProxy := "http://" + net.JoinHostPort(gateway, strconv.Itoa(httpPort))

	// Check each variable separately for better error messages
	httpProxyOut, httpErr := runSSHCommandOutput(paths, user, ip, "bash", "-lc", "'printenv HTTP_PROXY'")
	httpsProxyOut, httpsErr := runSSHCommandOutput(paths, user, ip, "bash", "-lc", "'printenv HTTPS_PROXY'")

	httpProxy := strings.TrimSpace(string(httpProxyOut))
	httpsProxy := strings.TrimSpace(string(httpsProxyOut))

	// Check if variables are set
	if httpErr != nil && httpsErr != nil {
		result.Passed = false
		result.Details = "proxy variables not set"
		result.Hint = hintCheckCloudInit
		return result
	}

	if httpErr != nil || httpProxy == "" {
		result.Passed = false
		result.Details = "HTTP_PROXY not set"
		result.Hint = hintCheckCloudInit
		return result
	}

	if httpsErr != nil || httpsProxy == "" {
		result.Passed = false
		result.Details = "HTTPS_PROXY not set"
		result.Hint = hintCheckCloudInit
		return result
	}

	// Check if they match expected
	if httpProxy != expectedProxy || httpsProxy != expectedProxy {
		result.Passed = false
		result.Details = fmt.Sprintf("HTTP_PROXY=%s, HTTPS_PROXY=%s", httpProxy, httpsProxy)
		result.Hint = "Expected " + expectedProxy
		return result
	}

	result.Passed = true
	result.Details = expectedProxy
	return result
}

// checkDNSConfig verifies DNS is configured correctly in the guest.
// Supports systemd-resolved (Debian/Ubuntu), NetworkManager (RHEL/AlmaLinux),
// and direct resolv.conf configuration.
func checkDNSConfig(paths *config.Paths, user, ip, gateway string) CheckResult {
	result := CheckResult{Name: CheckNameDNSConfig}

	// Try systemd-resolved config (Debian/Ubuntu)
	output, err := runSSHCommandOutput(paths, user, ip, "cat", "/etc/systemd/resolved.conf.d/00-abox.conf")
	if err == nil {
		if strings.Contains(string(output), gateway) {
			result.Passed = true
			result.Details = "DNS=" + gateway + " (systemd-resolved)"
			return result
		}
		result.Passed = false
		result.Details = "systemd-resolved config doesn't point to gateway"
		result.Hint = "systemd-resolved may not use the abox DNS filter"
		return result
	}

	// Try NetworkManager config (RHEL/AlmaLinux/Rocky)
	output, err = runSSHCommandOutput(paths, user, ip, "cat", "/etc/NetworkManager/conf.d/99-abox-dns.conf")
	if err == nil && strings.Contains(string(output), "dns=none") {
		// NetworkManager DNS is disabled; check resolv.conf directly
		output, err = runSSHCommandOutput(paths, user, ip, "cat", "/etc/resolv.conf")
		if err == nil && strings.Contains(string(output), gateway) {
			result.Passed = true
			result.Details = "DNS=" + gateway + " (NetworkManager/resolv.conf)"
			return result
		}
	}

	// Fallback: check resolv.conf directly
	output, err = runSSHCommandOutput(paths, user, ip, "cat", "/etc/resolv.conf")
	if err == nil && strings.Contains(string(output), gateway) {
		result.Passed = true
		result.Details = "DNS=" + gateway + " (resolv.conf)"
		return result
	}

	result.Passed = false
	result.Details = "abox DNS config not found"
	result.Hint = hintCheckCloudInit
	return result
}
