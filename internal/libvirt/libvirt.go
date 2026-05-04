// Package libvirt provides XML generation and virsh command wrappers for VM management.
package libvirt

import (
	"bytes"
	_ "embed"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"math/rand"
	"net"
	"os"
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

	// Validate MAC address
	if err := validation.ValidateMACAddress(inst.MACAddress); err != nil {
		return "", fmt.Errorf("invalid MAC address: %w", err)
	}

	// Calculate DHCP range from gateway IP
	gwIP := net.ParseIP(inst.Gateway)
	if gwIP == nil {
		return "", fmt.Errorf("invalid gateway IP: %s", inst.Gateway)
	}
	gw4 := gwIP.To4()
	if gw4 == nil {
		return "", fmt.Errorf("gateway is not IPv4: %s", inst.Gateway)
	}

	// Create a safe copy with escaped values for XML
	data := struct {
		Bridge     string
		Gateway    string
		MACAddress string
		IPAddress  string
		DHCPStart  string
		DHCPEnd    string
	}{
		Bridge:     escapeXML(inst.Bridge),
		Gateway:    escapeXML(inst.Gateway),
		MACAddress: escapeXML(inst.MACAddress),
		IPAddress:  escapeXML(inst.IPAddress),
		DHCPStart:  fmt.Sprintf("%d.%d.%d.100", gw4[0], gw4[1], gw4[2]),
		DHCPEnd:    fmt.Sprintf("%d.%d.%d.200", gw4[0], gw4[1], gw4[2]),
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
	Name             string
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

	return buf.String(), nil
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
// The filter allows DNS queries and HTTP proxy traffic only; all other outbound is dropped.
//
// The uuid parameter should be provided when updating an existing filter. To get the UUID
// of an existing filter, call GetNWFilterUUID first. Pass empty string for new filters.
//
// Architecture note: nwfilter rules are evaluated BEFORE iptables NAT PREROUTING.
// The VM sends DNS queries to port 53 (configured via cloud-init), so nwfilter must
// allow port 53. Iptables PREROUTING then redirects port 53 to the actual dnsfilter
// port (e.g., 42916). The HTTP proxy runs on its configured port with no redirect.
func NWFilterXML(inst *config.Instance, uuid string) (string, error) {
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

	// Create a safe copy with escaped values for XML
	// Note: We allow both port 53 (what the VM sends) and the dnsfilter port
	// (what iptables redirects to). This is needed because libvirt generates
	// iptables rules from nwfilter that are evaluated AFTER NAT PREROUTING.
	data := struct {
		Name     string
		UUID     string
		Gateway  string
		DNSPort  int
		HTTPPort int
	}{
		Name:     escapeXML(inst.Name),
		UUID:     uuid, // UUID is already from libvirt, no escaping needed
		Gateway:  escapeXML(inst.Gateway),
		DNSPort:  inst.DNS.Port,
		HTTPPort: inst.HTTP.Port,
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
	output, err := virsh(args...)
	if err != nil {
		return false
	}
	for line := range strings.SplitSeq(output, "\n") {
		if strings.TrimSpace(line) == name {
			return true
		}
	}
	return false
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

// DomainExists checks if a domain exists.
func DomainExists(name string) bool {
	return virshOutputContainsLine(name, "list", "--all", "--name")
}

// virsh domstate output values.
const (
	domStateRunning = "running"
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
  <model type='virtio'/>
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
  <model type='virtio'/>
  <driver name='vhost' queues='%d'/>
</interface>`, escapeXML(macAddress), escapeXML(networkName), netQueues(cpus))

	if err := cmd.RunWithStdin("virsh", ifaceXML, "-c", "qemu:///system", "update-device", domainName, "/dev/stdin", "--live"); err != nil {
		return fmt.Errorf("failed to remove nwfilter: %w", err)
	}
	return nil
}

// GetDomainIP gets the IP address of a running domain.
func GetDomainIP(name string) (string, error) {
	output, err := virsh("domifaddr", name, "--source", "agent")
	if err != nil {
		// Try lease file as fallback
		output, err = virsh("domifaddr", name, "--source", "lease")
		if err != nil {
			return "", fmt.Errorf("failed to get domain IP: %w", err)
		}
	}

	// Parse output to find IP
	lines := strings.SplitSeq(output, "\n")
	for line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			// Format: name mac protocol address
			addr := fields[3]
			if strings.Contains(addr, "/") {
				addr = strings.Split(addr, "/")[0]
			}
			if addr != "" && !strings.HasPrefix(addr, "127.") {
				// Validate it's actually an IP address (not a header like "Protocol")
				if net.ParseIP(addr) != nil {
					return addr, nil
				}
			}
		}
	}

	return "", errors.New("no IP address found")
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
