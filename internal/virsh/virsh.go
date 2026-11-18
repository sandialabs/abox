// Package virsh provides XML generation and virsh command wrappers for VM management.
package virsh

import (
	"bytes"
	_ "embed"
	"encoding/xml"
	"fmt"
	"html"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"text/template"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/validation"
)

//go:embed templates/domain.xml.tmpl
var domainXMLTemplate string

//go:embed templates/network.xml.tmpl
var networkXMLTemplate string

//go:embed templates/nwfilter.xml.tmpl
var nwfilterXMLTemplate string

// escapeXML escapes a string for safe use in XML attributes and content.
// This prevents XML injection attacks from user-controlled values.
func escapeXML(s string) string {
	return html.EscapeString(s)
}

// netQueues returns the number of virtio-net queues for the given CPU count.
// Queues are capped at 4 with a minimum of 1.
func netQueues(cpus int) int {
	q := min(cpus, 4)
	if q < 1 {
		return 1
	}
	return q
}

// NetworkXML generates libvirt network XML for an instance.
func NetworkXML(inst *config.Instance) (string, error) {
	// Validate instance name to prevent XML injection
	if err := validation.ValidateInstanceName(inst.Name); err != nil {
		return "", fmt.Errorf("invalid instance name: %w", err)
	}

	// Validate the gateway — the only address emitted into the network XML now
	// that guests are statically addressed (cloud-init) and libvirt runs no DHCP.
	if ip := net.ParseIP(inst.Gateway); ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("invalid gateway IP: %s", inst.Gateway)
	}

	// Create a safe copy with escaped values for XML
	data := struct {
		Bridge  string
		Gateway string
	}{
		Bridge:  escapeXML(inst.Bridge),
		Gateway: escapeXML(inst.Gateway),
	}

	t, err := template.New("network").Parse(networkXMLTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse network template: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute network template: %w", err)
	}

	return buf.String(), nil
}

// EmbeddedDomainTemplate returns the built-in domain XML template.
// This is used by the overrides dump command to let users customize the template.
func EmbeddedDomainTemplate() string {
	return domainXMLTemplate
}

// domainTemplateData holds the variables available to domain XML templates.
// This type is shared between ValidateTemplate and DomainXMLWithOptions to
// ensure they stay in sync.
type domainTemplateData struct {
	Name             string // bare instance name (e.g. "dev"); labels/descriptions only
	VMName           string // resolved libvirt domain name (e.g. "abox-1000-dev"); used for <name>
	UUID             string
	Memory           int
	CPUs             int
	NetQueues        int
	DiskPath         string
	CloudInitISO     string
	MACAddress       string
	Bridge           string
	MonitorSocket    string
	MonitorSocketUID int
	MonitorSocketGID int
}

// ValidateTemplate parses a domain XML template and validates it by executing
// with zero-value data. This catches syntax errors and references to nonexistent
// fields before any resources are allocated.
func ValidateTemplate(content string) error {
	t, err := template.New("domain").Parse(content)
	if err != nil {
		return fmt.Errorf("template syntax error: %w", err)
	}

	// Execute with zero-value struct to catch field reference errors.
	// Conditional blocks ({{if .Field}}) will evaluate to false, so errors
	// inside them won't be caught — but virsh define will reject invalid XML.
	var buf bytes.Buffer
	if err := t.Execute(&buf, domainTemplateData{}); err != nil {
		return fmt.Errorf("template execution error: %w", err)
	}

	return nil
}

// DomainXMLOptions holds options for domain XML generation.
type DomainXMLOptions struct {
	// AssumeCloudInitExists forces inclusion of the cloud-init CDROM device
	// even if the ISO file doesn't exist yet (useful for dry-run).
	AssumeCloudInitExists bool

	// MonitorEnabled includes a virtio-serial channel for Tetragon monitoring.
	// The socket path is taken from paths.MonitorSocket.
	MonitorEnabled bool

	// UUID is the existing domain UUID to preserve when redefining.
	// This prevents "domain already exists with uuid" errors.
	// Pass empty string for new domains.
	UUID string

	// CustomTemplate overrides the embedded domain XML template.
	// When non-empty, this template string is used instead of the built-in template.
	// The template must use the same Go template variables as the default.
	CustomTemplate string
}

// DomainXMLWithOptions generates libvirt domain XML with additional options.
func DomainXMLWithOptions(inst *config.Instance, paths *config.Paths, opts DomainXMLOptions) (string, error) {
	// Validate instance name to prevent XML injection
	if err := validation.ValidateInstanceName(inst.Name); err != nil {
		return "", fmt.Errorf("invalid instance name: %w", err)
	}

	// Validate MAC address
	if err := validation.ValidateMACAddress(inst.MACAddress); err != nil {
		return "", fmt.Errorf("invalid MAC address: %w", err)
	}

	// Check if cloud-init ISO exists (or assume it does for dry-run)
	cloudInitISO := ""
	if paths.CloudInitISO != "" {
		if opts.AssumeCloudInitExists {
			cloudInitISO = escapeXML(paths.CloudInitISO)
		} else if _, err := os.Stat(paths.CloudInitISO); err == nil {
			cloudInitISO = escapeXML(paths.CloudInitISO)
		}
	}

	// Include monitor socket path if monitoring is enabled
	monitorSocket := ""
	monitorSocketUID := 0
	monitorSocketGID := 0
	if opts.MonitorEnabled && paths.MonitorSocket != "" {
		monitorSocket = escapeXML(paths.MonitorSocket)
		// Set socket ownership to current user so monitor daemon can access it
		monitorSocketUID = os.Getuid()
		monitorSocketGID = os.Getgid()
	}

	// Calculate multi-queue virtio-net queues: one per vCPU, capped at 4
	nq := netQueues(inst.CPUs)

	// Create a safe copy with escaped values for XML
	data := domainTemplateData{
		Name:             escapeXML(inst.Name),
		VMName:           escapeXML(inst.ResolvedVMName()),
		UUID:             opts.UUID, // UUID is already from libvirt, no escaping needed
		Memory:           inst.Memory,
		CPUs:             inst.CPUs,
		NetQueues:        nq,
		DiskPath:         escapeXML(paths.Disk),
		CloudInitISO:     cloudInitISO,
		MACAddress:       escapeXML(inst.MACAddress),
		Bridge:           escapeXML(inst.Bridge),
		MonitorSocket:    monitorSocket,
		MonitorSocketUID: monitorSocketUID,
		MonitorSocketGID: monitorSocketGID,
	}

	tmplContent := domainXMLTemplate
	if opts.CustomTemplate != "" {
		tmplContent = opts.CustomTemplate
	}

	t, err := template.New("domain").Parse(tmplContent)
	if err != nil {
		return "", fmt.Errorf("failed to parse domain template: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute domain template: %w", err)
	}

	// A custom template must emit the resolved (per-user) domain name in its
	// <name> element. A template written against the pre-multi-user variable list
	// hardcodes abox-{{.Name}}, which renders a DIFFERENT name than every
	// lifecycle lookup resolves to (ResolvedVMName) — the VM would define under
	// one name and fail every start/stop/remove afterward, and on a shared host
	// collide on the legacy name. Fail closed here rather than defining an
	// unreachable domain. The built-in template uses {{.VMName}}, so this only
	// ever gates overrides.
	if opts.CustomTemplate != "" {
		if got := domainNameFromXML(buf.String()); got != inst.ResolvedVMName() {
			return "", fmt.Errorf("custom domain template <name> is %q, must be %q "+
				"(use {{.VMName}} for the <name> element, not abox-{{.Name}})", got, inst.ResolvedVMName())
		}
	}

	return buf.String(), nil
}

// domainNameFromXML extracts the <name> element of a libvirt domain XML document,
// or "" if absent/malformed. Used to verify a custom template names the domain
// correctly (see DomainXMLWithOptions).
func domainNameFromXML(domainXML string) string {
	var parsed struct {
		Name string `xml:"name"`
	}
	if err := xml.Unmarshal([]byte(domainXML), &parsed); err != nil {
		return ""
	}
	return parsed.Name
}

// GetDomainUUID returns the UUID of an existing domain, or empty string if not found.
// This is needed when redefining a domain in-place: libvirt requires the same UUID to update
// an existing domain rather than failing with "domain already exists with uuid".
//
// Security note: The returned UUID comes directly from libvirt's XML output and is
// parsed via Go's xml.Unmarshal. UUIDs from libvirt are guaranteed to be in standard
// format (8-4-4-4-12 hex digits), so no escaping is needed when inserting into new XML.
func GetDomainUUID(name string) string {
	output, err := virsh("dumpxml", name)
	if err != nil {
		logging.Debug("failed to get domain XML", "name", name, "error", err)
		return ""
	}
	// Parse UUID from domain XML - xml.Unmarshal handles entity decoding
	var domain struct {
		UUID string `xml:"uuid"`
	}
	if err := xml.Unmarshal([]byte(output), &domain); err != nil {
		logging.Debug("failed to parse domain XML", "name", name, "error", err)
		return ""
	}
	return strings.TrimSpace(domain.UUID)
}

// DomainDiskPaths returns the source file paths of a domain's file-backed disk
// devices (disk and cdrom). Used to verify that a domain found under a shared
// (legacy) name actually belongs to an instance — its disk source matching the
// instance's disk — before acting on it: legacy names are derived from the
// instance name alone, so on a shared host a same-named domain may be another
// user's. A failure to inspect is an ERROR, distinct from a readable domain
// with no matching disks: ownership-gated teardown must fail closed on a probe
// failure rather than treat the domain as foreign (or as absent).
func DomainDiskPaths(name string) ([]string, error) {
	output, err := virsh("dumpxml", name)
	if err != nil {
		return nil, fmt.Errorf("failed to get domain XML for %s: %w", name, err)
	}
	var domain struct {
		Disks []struct {
			Source struct {
				File string `xml:"file,attr"`
			} `xml:"source"`
		} `xml:"devices>disk"`
	}
	if err := xml.Unmarshal([]byte(output), &domain); err != nil {
		return nil, fmt.Errorf("failed to parse domain XML for %s: %w", name, err)
	}
	var paths []string
	for _, d := range domain.Disks {
		if d.Source.File != "" {
			paths = append(paths, d.Source.File)
		}
	}
	return paths, nil
}

// GetNWFilterUUID returns the UUID of an existing nwfilter, or empty string if not found.
// This is needed when updating a filter in-place: libvirt requires the same UUID to update
// an existing filter rather than failing with "nwfilter already exists".
//
// Security note: The returned UUID comes directly from libvirt's XML output and is
// parsed via Go's xml.Unmarshal. UUIDs from libvirt are guaranteed to be in standard
// format (8-4-4-4-12 hex digits), so no escaping is needed when inserting into new XML.
func GetNWFilterUUID(name string) string {
	output, err := virsh("nwfilter-dumpxml", name)
	if err != nil {
		logging.Debug("failed to get nwfilter XML", "name", name, "error", err)
		return ""
	}
	// Parse UUID from nwfilter XML - xml.Unmarshal handles entity decoding
	var filter struct {
		UUID string `xml:"uuid"`
	}
	if err := xml.Unmarshal([]byte(output), &filter); err != nil {
		logging.Debug("failed to parse nwfilter XML", "name", name, "error", err)
		return ""
	}
	return filter.UUID
}

// NWFilterXML generates the traffic control nwfilter XML.
// The filter is stateful and default-deny in both directions. Outbound, the guest
// may reach only DNS and the HTTP proxy/ICMP on the gateway. Inbound, the only new
// connection permitted is host->guest SSH (port 22); everything else is dropped.
// Replies to established connections are admitted explicitly in both directions
// (see below). There are no DHCP rules: guests are statically addressed via
// cloud-init and the network runs no DHCP server.
//
// The uuid parameter should be provided when updating an existing filter. To get the UUID
// of an existing filter, call GetNWFilterUUID first. Pass empty string for new filters.
//
// State note: libvirt tracks connection state per rule (statematch defaults to
// true). Rather than depend on the exact reverse-direction instantiation libvirt
// derives per rule, this filter makes the stateful policy explicit — the standard
// stateful-firewall shape: each initiator rule sets state='NEW', and return
// traffic is admitted by dedicated ESTABLISHED,RELATED accepts in both directions.
// New inbound connections are therefore limited to host->guest SSH; nothing else
// may initiate into the guest.
//
// Architecture note: nwfilter rules are evaluated BEFORE iptables NAT PREROUTING.
// The VM sends DNS queries to port 53 (configured via cloud-init), so nwfilter must
// allow port 53. Iptables PREROUTING then redirects port 53 to the actual dnsfilter
// port (e.g., 42916). The HTTP proxy runs on its configured port with no redirect.
// The egress rule set (which ports/protocols are permitted) is driven by the
// caller's EgressPolicy: guestDNSPort is the guest-facing DNS port the guest
// sends to (redirected to the dnsfilter port by iptables). Gateway ICMP is always
// permitted (ping is a useful diagnostic), matching the host iptables rules driven
// from the same policy (see backend.BuildEgressPolicy).
func NWFilterXML(inst *config.Instance, uuid string, guestDNSPort int) (string, error) {
	// Validate instance name to prevent XML injection
	if err := validation.ValidateInstanceName(inst.Name); err != nil {
		return "", fmt.Errorf("invalid instance name: %w", err)
	}

	// Validate port ranges (must be valid TCP/UDP ports, use non-privileged range)
	if inst.DNS.Port < 1 || inst.DNS.Port > 65535 {
		return "", fmt.Errorf("invalid DNS port: %d (must be 1-65535)", inst.DNS.Port)
	}
	if inst.HTTP.Port < 1 || inst.HTTP.Port > 65535 {
		return "", fmt.Errorf("invalid HTTP port: %d (must be 1-65535)", inst.HTTP.Port)
	}
	if guestDNSPort < 1 || guestDNSPort > 65535 {
		return "", fmt.Errorf("invalid guest DNS port: %d (must be 1-65535)", guestDNSPort)
	}

	// Create a safe copy with escaped values for XML
	// Note: We allow both the guest-facing DNS port (what the VM sends) and the
	// dnsfilter port (what iptables redirects to). This is needed because libvirt
	// generates iptables rules from nwfilter that are evaluated AFTER NAT PREROUTING.
	data := struct {
		Name         string
		FilterName   string
		UUID         string
		Gateway      string
		DNSPort      int
		HTTPPort     int
		GuestDNSPort int
	}{
		Name:         escapeXML(inst.Name),
		FilterName:   escapeXML(inst.ResolvedFilterName()),
		UUID:         uuid, // UUID is already from libvirt, no escaping needed
		Gateway:      escapeXML(inst.Gateway),
		DNSPort:      inst.DNS.Port,
		HTTPPort:     inst.HTTP.Port,
		GuestDNSPort: guestDNSPort,
	}

	t, err := template.New("nwfilter").Parse(nwfilterXMLTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse nwfilter template: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute nwfilter template: %w", err)
	}

	return buf.String(), nil
}

// virsh runs a virsh command and returns the output.
// Uses the Commander interface for testability.
// Connects to qemu:///system to manage system VMs/networks (requires libvirt group membership).
func virsh(args ...string) (string, error) {
	// Prepend connection to system libvirt daemon
	fullArgs := append([]string{"-c", "qemu:///system"}, args...)
	return cmd.Run("virsh", fullArgs...)
}

// virshOutputContainsLine runs a virsh command and checks if any line
// in the output exactly matches the given name (after trimming whitespace).
func virshOutputContainsLine(name string, args ...string) bool {
	ok, err := virshOutputContainsLineErr(name, args...)
	return err == nil && ok
}

// virshOutputContainsLineErr is virshOutputContainsLine with the virsh error
// propagated, for callers that must fail CLOSED: "absent" and "could not list"
// are different answers when the result gates a destructive action.
func virshOutputContainsLineErr(name string, args ...string) (bool, error) {
	output, err := virsh(args...)
	if err != nil {
		return false, err
	}
	for line := range strings.SplitSeq(output, "\n") {
		if strings.TrimSpace(line) == name {
			return true, nil
		}
	}
	return false, nil
}

// DefineNetwork defines a libvirt network from XML.
func DefineNetwork(xml string) error {
	logging.Debug("defining libvirt network")
	if err := cmd.RunWithStdin("virsh", xml, "-c", "qemu:///system", "net-define", "/dev/stdin"); err != nil {
		return fmt.Errorf("failed to define network: %w", err)
	}
	return nil
}

// StartNetwork starts a libvirt network.
func StartNetwork(name string) error {
	logging.Debug("starting libvirt network", "network", name)
	_, err := virsh("net-start", name)
	if err != nil {
		return fmt.Errorf("failed to start network: %w", err)
	}
	return nil
}

// StopNetwork stops a libvirt network.
func StopNetwork(name string) error {
	logging.Debug("stopping libvirt network", "network", name)
	_, err := virsh("net-destroy", name)
	if err != nil {
		return fmt.Errorf("failed to stop network: %w", err)
	}
	return nil
}

// DeleteNetwork undefines a libvirt network.
func DeleteNetwork(name string) error {
	logging.Debug("deleting libvirt network", "network", name)
	// Stop the network first; error ignored because network may not be running
	_, _ = virsh("net-destroy", name)
	_, err := virsh("net-undefine", name)
	if err != nil {
		return fmt.Errorf("failed to delete network: %w", err)
	}
	return nil
}

// NetworkExists checks if a network exists.
func NetworkExists(name string) bool {
	return virshOutputContainsLine(name, "net-list", "--all", "--name")
}

// NetworkDefined is NetworkExists with the listing error propagated. Use it
// where a false answer authorizes skipping (or performing) a destructive step —
// a transient virsh failure must not read as "absent" there.
func NetworkDefined(name string) (bool, error) {
	return virshOutputContainsLineErr(name, "net-list", "--all", "--name")
}

// NetworkIsActive checks if a network is active.
func NetworkIsActive(name string) bool {
	return virshOutputContainsLine(name, "net-list", "--name")
}

// DefineDomain defines a libvirt domain from XML.
func DefineDomain(xml string) error {
	logging.Debug("defining libvirt domain")
	if err := cmd.RunWithStdin("virsh", xml, "-c", "qemu:///system", "define", "/dev/stdin"); err != nil {
		return fmt.Errorf("failed to define domain: %w", err)
	}
	return nil
}

// StartDomain starts a libvirt domain.
func StartDomain(name string) error {
	logging.Debug("starting libvirt domain", "domain", name)
	_, err := virsh("start", name)
	if err != nil {
		return fmt.Errorf("failed to start domain: %w", err)
	}
	return nil
}

// StopDomain stops a libvirt domain gracefully.
func StopDomain(name string) error {
	logging.Debug("stopping libvirt domain", "domain", name)
	_, err := virsh("shutdown", name)
	if err != nil {
		return fmt.Errorf("failed to stop domain: %w", err)
	}
	return nil
}

// ForceStopDomain forcefully stops a libvirt domain.
func ForceStopDomain(name string) error {
	logging.Debug("force stopping libvirt domain", "domain", name)
	_, err := virsh("destroy", name)
	if err != nil {
		return fmt.Errorf("failed to force stop domain: %w", err)
	}
	return nil
}

// DeleteDomain undefines a libvirt domain.
func DeleteDomain(name string) error {
	logging.Debug("deleting libvirt domain", "domain", name)
	// Force stop the domain first; error ignored because domain may not be running
	_, _ = virsh("destroy", name)
	_, err := virsh("undefine", name, "--remove-all-storage")
	if err != nil {
		return fmt.Errorf("failed to delete domain: %w", err)
	}
	return nil
}

// UndefineDomain removes a libvirt domain definition WITHOUT deleting its storage.
// Used by the resource-name upgrade, which renames an instance's domain by
// undefining the old name and letting the next start redefine it under the new
// name against the SAME (unmoved) disk — so --remove-all-storage must NOT be used
// here. --snapshots-metadata is deliberately NOT passed either: snapshot metadata
// records would be silently dropped (breaking `abox snapshot list/restore` for
// them), so a domain that still carries snapshots must fail the undefine loudly —
// the upgrade checks for snapshots first and refuses with guidance. The caller is
// responsible for ensuring the domain is stopped.
func UndefineDomain(name string) error {
	logging.Debug("undefining libvirt domain (keeping storage)", "domain", name)
	if _, err := virsh("undefine", name); err != nil {
		return fmt.Errorf("failed to undefine domain: %w", err)
	}
	return nil
}

// ListNetworkSubnets returns the IPv4 CIDRs of every libvirt network DEFINED on
// the host, active or not. Because libvirtd (qemu:///system) is shared across
// users, this reflects other users' networks too — used by subnet allocation to
// avoid double-booking a range that a stopped network still claims. CIDRs are
// returned at their real prefix length (not normalized to /24) so the allocator
// can also skip a candidate that falls inside a wider network. Best-effort:
// returns nil on any error (fail-open), and skips networks with no usable IPv4
// <ip>.
func ListNetworkSubnets() []*net.IPNet {
	return ListNetworkSubnetsExcluding("")
}

// ListNetworkSubnetsExcluding is ListNetworkSubnets minus the named network: used
// by the post-define double-book check, which must not count the network it just
// defined as a conflict with itself. An empty exclude skips nothing.
func ListNetworkSubnetsExcluding(exclude string) []*net.IPNet {
	out, err := virsh("net-list", "--all", "--name")
	if err != nil {
		logging.Debug("listing libvirt networks for subnet allocation failed; treating none as claimed", "error", err)
		return nil
	}
	var subnets []*net.IPNet
	for line := range strings.SplitSeq(out, "\n") {
		name := strings.TrimSpace(line)
		if name == "" || name == exclude {
			continue
		}
		subnets = append(subnets, networkSubnets(name)...)
	}
	return subnets
}

// NetworkSubnets returns the IPv4 CIDRs a single named network declares. Used
// to verify that a network found under a shared (legacy) name actually belongs
// to an instance — one of its subnets matching the instance's recorded subnet —
// before tearing it down (see DomainDiskPaths for the same reasoning on
// domains). A failure to inspect is an ERROR, distinct from a readable network
// with no usable IPv4 <ip>: ownership-gated teardown must fail closed on a
// probe failure.
func NetworkSubnets(name string) ([]*net.IPNet, error) {
	out, err := virsh("net-dumpxml", name)
	if err != nil {
		return nil, fmt.Errorf("failed to get network XML for %s: %w", name, err)
	}
	subnets, err := parseNetworkSubnets(out)
	if err != nil {
		return nil, fmt.Errorf("failed to parse network XML for %s: %w", name, err)
	}
	return subnets, nil
}

// networkSubnets returns the IPv4 CIDRs of a libvirt network's <ip> elements, or
// nil if it has none usable or cannot be inspected (fail-open, matching its
// allocation-probe callers).
func networkSubnets(name string) []*net.IPNet {
	out, err := virsh("net-dumpxml", name)
	if err != nil {
		return nil
	}
	subnets, _ := parseNetworkSubnets(out)
	return subnets
}

// parseNetworkSubnets extracts the IPv4 CIDRs from a network's XML. A network
// may declare SEVERAL <ip> elements (a dual-stack network has both an IPv4 and
// an IPv6 one, in either order), so all are collected and the non-IPv4 ones
// skipped. libvirt gives the size as a netmask or a prefix; both are handled.
// An unmarshal failure is an error (NetworkSubnets' ownership-gating callers
// must fail closed on it), distinct from parseable XML with no usable IPv4.
func parseNetworkSubnets(out string) ([]*net.IPNet, error) {
	var parsed struct {
		IPs []struct {
			Family  string `xml:"family,attr"`
			Address string `xml:"address,attr"`
			Netmask string `xml:"netmask,attr"`
			Prefix  string `xml:"prefix,attr"`
		} `xml:"ip"`
	}
	if err := xml.Unmarshal([]byte(out), &parsed); err != nil {
		return nil, err
	}
	var cidrs []*net.IPNet
	for _, e := range parsed.IPs {
		// family is absent for IPv4 and "ipv6" for IPv6; the To4 check below is
		// the real guard, this just skips the obvious case early.
		if e.Family == "ipv6" {
			continue
		}
		ip := net.ParseIP(e.Address).To4()
		if ip == nil {
			continue
		}
		var mask net.IPMask
		switch {
		case e.Netmask != "":
			mask = net.IPMask(net.ParseIP(e.Netmask).To4())
		case e.Prefix != "":
			prefix, perr := strconv.Atoi(e.Prefix)
			if perr != nil || prefix < 0 || prefix > 32 {
				continue
			}
			mask = net.CIDRMask(prefix, 32)
		}
		if mask == nil {
			continue
		}
		cidrs = append(cidrs, &net.IPNet{IP: ip.Mask(mask), Mask: mask})
	}
	return cidrs, nil
}

// DomainExists checks if a domain exists.
func DomainExists(name string) bool {
	return virshOutputContainsLine(name, "list", "--all", "--name")
}

// DomainDefined is DomainExists with the listing error propagated (see
// NetworkDefined for when that matters).
func DomainDefined(name string) (bool, error) {
	return virshOutputContainsLineErr(name, "list", "--all", "--name")
}

// virsh domstate output values.
const (
	domStateRunning = "running"
	domStateShutOff = "shut off"
	domStateUnknown = "unknown"
)

// DomainIsRunning checks if a domain is running.
func DomainIsRunning(name string) bool {
	output, err := virsh("domstate", name)
	if err != nil {
		return false
	}
	return strings.TrimSpace(output) == domStateRunning
}

// DomainIsShutOff reports whether a domain is positively in the "shut off"
// state. Unlike !DomainIsRunning this fails CLOSED: a paused or pmsuspended
// domain (an active qemu still holding its disk), and a transient domstate
// error, all report false. Use it to gate operations that are only safe
// against a fully inactive domain (e.g. the resource-name upgrade teardown).
func DomainIsShutOff(name string) bool {
	output, err := virsh("domstate", name)
	if err != nil {
		return false
	}
	return strings.TrimSpace(output) == domStateShutOff
}

// DomainState returns the state of a domain.
func DomainState(name string) string {
	output, err := virsh("domstate", name)
	if err != nil {
		return domStateUnknown
	}
	return strings.TrimSpace(output)
}

// DefineNWFilter defines a network filter from XML.
// If a filter with the same name already exists, it is updated in-place.
// This is safe even when the filter is attached to running VMs.
func DefineNWFilter(xml string) error {
	logging.Debug("defining libvirt nwfilter")
	if err := cmd.RunWithStdin("virsh", xml, "-c", "qemu:///system", "nwfilter-define", "/dev/stdin"); err != nil {
		return fmt.Errorf("failed to define nwfilter: %w", err)
	}
	return nil
}

// DeleteNWFilter undefines a network filter.
func DeleteNWFilter(name string) error {
	_, err := virsh("nwfilter-undefine", name)
	return err
}

// NWFilterExists checks if an nwfilter exists.
func NWFilterExists(name string) bool {
	output, err := virsh("nwfilter-list")
	if err != nil {
		return false
	}
	// Parse nwfilter-list output line by line.
	// Format: " UUID                                  Name"
	// Match the Name column exactly to avoid substring false positives.
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == name {
			return true
		}
	}
	return false
}

// ApplyNWFilter applies an nwfilter to a running domain's interface.
// The cpus parameter is needed to include the correct vhost driver queues
// in the update-device XML, matching the running domain's interface definition.
//
// The interface model/driver below are hardcoded to virtio-non-transitional/vhost
// to match the default domain template. A custom domain template
// (overrides.libvirt.template) MUST keep the interface model/driver identical, or
// this update-device will fail ("cannot modify network device model/driver
// attributes") and egress apply/remove will not work — documented in
// docs/abox-yaml.md.
func ApplyNWFilter(domainName, networkName, filterName, macAddress string, cpus int) error {
	logging.Debug("applying nwfilter", "domain", domainName, "filter", filterName)
	// Validate MAC address to prevent XML injection
	if err := validation.ValidateMACAddress(macAddress); err != nil {
		return fmt.Errorf("invalid MAC address: %w", err)
	}

	// Generate interface XML with filter using escaped values.
	// The <driver> element must match the running domain's interface definition,
	// otherwise libvirt rejects the update with "cannot modify virtio network
	// device driver attributes".
	ifaceXML := fmt.Sprintf(`<interface type='network'>
  <mac address='%s'/>
  <source network='%s'/>
  <model type='virtio-non-transitional'/>
  <driver name='vhost' queues='%d'/>
  <filterref filter='%s'/>
</interface>`, escapeXML(macAddress), escapeXML(networkName), netQueues(cpus), escapeXML(filterName))

	if err := cmd.RunWithStdin("virsh", ifaceXML, "-c", "qemu:///system", "update-device", domainName, "/dev/stdin", "--live"); err != nil {
		return fmt.Errorf("failed to apply nwfilter: %w", err)
	}
	return nil
}

// RemoveNWFilter removes an nwfilter from a running domain's interface.
// The cpus parameter is needed to include the correct vhost driver queues
// in the update-device XML, matching the running domain's interface definition.
func RemoveNWFilter(domainName, networkName, macAddress string, cpus int) error {
	logging.Debug("removing nwfilter", "domain", domainName)
	// Validate MAC address to prevent XML injection
	if err := validation.ValidateMACAddress(macAddress); err != nil {
		return fmt.Errorf("invalid MAC address: %w", err)
	}

	// Generate interface XML without filter using escaped values.
	// The <driver> element must match the running domain's interface definition.
	ifaceXML := fmt.Sprintf(`<interface type='network'>
  <mac address='%s'/>
  <source network='%s'/>
  <model type='virtio-non-transitional'/>
  <driver name='vhost' queues='%d'/>
</interface>`, escapeXML(macAddress), escapeXML(networkName), netQueues(cpus))

	if err := cmd.RunWithStdin("virsh", ifaceXML, "-c", "qemu:///system", "update-device", domainName, "/dev/stdin", "--live"); err != nil {
		return fmt.Errorf("failed to remove nwfilter: %w", err)
	}
	return nil
}

// GenerateMAC generates a random MAC address with the libvirt prefix.
// Uses libvirt's OUI prefix 52:54:00 which is their registered prefix.
// Go 1.20+ auto-seeds the global rand, so no manual seeding needed.
func GenerateMAC() string {
	return fmt.Sprintf("52:54:00:%02x:%02x:%02x",
		rand.Intn(256), rand.Intn(256), rand.Intn(256)) //nolint:gosec // MAC address doesn't need crypto randomness
}

// SnapshotInfo holds information about a domain snapshot.
type SnapshotInfo struct {
	Name         string
	CreationTime string
	State        string
	Parent       string
	Current      bool
}

// CreateSnapshot creates a new snapshot for a domain.
func CreateSnapshot(domainName, snapshotName, description string) error {
	// Validate snapshot name for defense-in-depth
	if err := validation.ValidateSnapshotName(snapshotName); err != nil {
		return fmt.Errorf("invalid snapshot name: %w", err)
	}

	args := []string{"snapshot-create-as", domainName, snapshotName}
	if description != "" {
		args = append(args, "--description", description)
	}
	_, err := virsh(args...)
	return err
}

// DomainHasSnapshots reports whether a domain carries libvirt snapshot metadata.
// Best-effort false on error: callers use it as a pre-check to produce a good
// error message, with the bare `virsh undefine` still failing loudly on any
// snapshot-carrying domain the check missed.
func DomainHasSnapshots(domainName string) bool {
	output, err := virsh("snapshot-list", domainName, "--name")
	if err != nil {
		return false
	}
	return strings.TrimSpace(output) != ""
}

// ListSnapshots returns a list of snapshots for a domain.
func ListSnapshots(domainName string) ([]SnapshotInfo, error) {
	// Get list of snapshot names
	output, err := virsh("snapshot-list", domainName, "--name")
	if err != nil {
		return nil, err
	}

	var snapshots []SnapshotInfo
	lines := strings.SplitSeq(strings.TrimSpace(output), "\n")
	for line := range lines {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}
		info, err := GetSnapshotInfo(domainName, name)
		if err != nil {
			continue
		}
		snapshots = append(snapshots, info)
	}

	return snapshots, nil
}

// DeleteSnapshot deletes a snapshot from a domain.
func DeleteSnapshot(domainName, snapshotName string) error {
	// Validate snapshot name for defense-in-depth
	if err := validation.ValidateSnapshotName(snapshotName); err != nil {
		return fmt.Errorf("invalid snapshot name: %w", err)
	}

	_, err := virsh("snapshot-delete", domainName, snapshotName)
	return err
}

// RevertSnapshot reverts a domain to a snapshot.
func RevertSnapshot(domainName, snapshotName string) error {
	// Validate snapshot name for defense-in-depth
	if err := validation.ValidateSnapshotName(snapshotName); err != nil {
		return fmt.Errorf("invalid snapshot name: %w", err)
	}

	_, err := virsh("snapshot-revert", domainName, snapshotName)
	return err
}

// SnapshotExists checks if a snapshot exists for a domain.
func SnapshotExists(domainName, snapshotName string) bool {
	// Validate snapshot name for defense-in-depth
	if err := validation.ValidateSnapshotName(snapshotName); err != nil {
		return false
	}

	return virshOutputContainsLine(snapshotName, "snapshot-list", domainName, "--name")
}

// GetSnapshotInfo retrieves detailed information about a snapshot.
func GetSnapshotInfo(domainName, snapshotName string) (SnapshotInfo, error) {
	// Validate snapshot name for defense-in-depth
	if err := validation.ValidateSnapshotName(snapshotName); err != nil {
		return SnapshotInfo{}, fmt.Errorf("invalid snapshot name: %w", err)
	}

	output, err := virsh("snapshot-info", domainName, snapshotName)
	if err != nil {
		return SnapshotInfo{}, err
	}

	info := SnapshotInfo{Name: snapshotName}

	for line := range strings.SplitSeq(output, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "Name":
			info.Name = value
		case "Creation Time":
			info.CreationTime = value
		case "State":
			info.State = value
		case "Parent":
			info.Parent = value
		case "Current":
			info.Current = value == "yes"
		}
	}

	return info, nil
}
