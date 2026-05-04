// Package validation provides input validation for security-sensitive values.
package validation

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Instance name validation:
// - Must start with a letter
// - Can contain letters, numbers, underscores, and hyphens
// - Must be 1-63 characters total (max 63 to allow for "abox-" prefix in libvirt names)
var validInstanceNameRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,62}$`)

// MAC address validation:
// - Standard colon-separated MAC address format
var validMACAddressRegex = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)

// ValidateInstanceName validates an instance name for safe use in:
// - libvirt domain names (abox-<name>)
// - bridge names (generated via config.GenerateBridgeName to ensure max 15 chars)
// - nwfilter names (abox-<name>-traffic)
// - file paths (~/.local/share/abox/instances/<name>/)
// - iptables arguments
//
// Returns nil if valid, or an error describing the problem.
func ValidateInstanceName(name string) error {
	if name == "" {
		return errors.New("instance name cannot be empty")
	}

	if len(name) > 63 {
		return fmt.Errorf("instance name too long (max 63 characters, got %d)", len(name))
	}

	if !validInstanceNameRegex.MatchString(name) {
		return fmt.Errorf("invalid instance name %q: must start with a letter and contain only letters, numbers, underscores, and hyphens", name)
	}

	return nil
}

// ValidateMACAddress validates a MAC address for safe use in libvirt XML.
// Returns nil if valid, or an error describing the problem.
func ValidateMACAddress(mac string) error {
	if mac == "" {
		return errors.New("MAC address cannot be empty")
	}

	if !validMACAddressRegex.MatchString(mac) {
		return fmt.Errorf("invalid MAC address %q: must be in format XX:XX:XX:XX:XX:XX", mac)
	}

	return nil
}

// Snapshot name validation:
// - Must start with an alphanumeric character
// - Can contain alphanumerics, underscores, and hyphens
// - Maximum 255 characters
var validSnapshotNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

// ValidateSnapshotName validates a snapshot name for safe use in libvirt commands.
// Returns nil if valid, or an error describing the problem.
func ValidateSnapshotName(name string) error {
	if name == "" {
		return errors.New("snapshot name cannot be empty")
	}
	if len(name) > 255 {
		return errors.New("snapshot name too long (max 255 characters)")
	}
	if !validSnapshotNameRegex.MatchString(name) {
		return fmt.Errorf("invalid snapshot name %q: must start with alphanumeric and contain only alphanumerics, underscores, or hyphens", name)
	}
	return nil
}

// Domain validation:
// - Each label can contain alphanumerics and hyphens
// - Labels are separated by dots
// - Wildcard prefix "*." is allowed
// - No control characters (especially newlines which could allow command injection)
var validDomainLabelRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$|^[a-zA-Z0-9]$`)

// ValidateDomain validates a domain name for safe use in DNS commands.
// This prevents command injection attacks via newlines or control characters.
// Returns nil if valid, or an error describing the problem.
func ValidateDomain(domain string) error {
	if domain == "" {
		return errors.New("domain cannot be empty")
	}

	// Reject control characters (including newlines which could inject commands)
	for _, r := range domain {
		if r < 32 || r == 127 {
			return errors.New("domain contains invalid control character")
		}
	}

	// Strip optional wildcard prefix for validation
	toValidate := domain
	if after, ok := strings.CutPrefix(domain, "*."); ok {
		toValidate = after
	}

	// Remove trailing dot if present (FQDN)
	toValidate = strings.TrimSuffix(toValidate, ".")

	if toValidate == "" {
		return errors.New("domain cannot be empty after removing wildcard/dot")
	}

	// Check total length (max 253 characters for domain)
	if len(toValidate) > 253 {
		return fmt.Errorf("domain too long (max 253 characters, got %d)", len(toValidate))
	}

	// Validate each label
	labels := strings.Split(toValidate, ".")
	if len(labels) < 1 {
		return errors.New("domain must have at least one label")
	}

	for _, label := range labels {
		if len(label) == 0 {
			return errors.New("domain contains empty label (consecutive dots)")
		}
		if len(label) > 63 {
			return fmt.Errorf("domain label %q too long (max 63 characters)", label)
		}
		if !validDomainLabelRegex.MatchString(label) {
			return fmt.Errorf("invalid domain label %q: must contain only letters, numbers, and hyphens (not at start/end)", label)
		}
	}

	return nil
}

// SSH user validation:
// - Must start with a letter or underscore
// - Can contain letters, numbers, underscores, and hyphens
// - Maximum 32 characters (POSIX limit)
var validSSHUserRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$`)

// ValidateSSHUser validates an SSH username for safe use in shell commands.
// This prevents command injection attacks via malicious usernames.
// Returns nil if valid, or an error describing the problem.
func ValidateSSHUser(user string) error {
	if user == "" {
		return errors.New("SSH user cannot be empty")
	}

	if len(user) > 32 {
		return fmt.Errorf("SSH user too long (max 32 characters, got %d)", len(user))
	}

	if !validSSHUserRegex.MatchString(user) {
		return fmt.Errorf("invalid SSH user %q: must start with a letter or underscore and contain only letters, numbers, underscores, and hyphens", user)
	}

	return nil
}

// Resource limits for VMs
const (
	MinCPUs   = 1
	MaxCPUs   = 128
	MinMemory = 256    // 256 MB minimum
	MaxMemory = 262144 // 256 GB maximum
)

// ValidateResourceLimits validates CPU and memory values for VM creation.
// Returns nil if valid, or an error describing the problem.
func ValidateResourceLimits(cpus, memoryMB int) error {
	if cpus < MinCPUs || cpus > MaxCPUs {
		return fmt.Errorf("CPUs must be between %d and %d (got %d)", MinCPUs, MaxCPUs, cpus)
	}
	if memoryMB < MinMemory || memoryMB > MaxMemory {
		return fmt.Errorf("memory must be between %d and %d MB (got %d)", MinMemory, MaxMemory, memoryMB)
	}
	return nil
}

// ValidateDiskSize validates a disk size string (e.g., "20G", "100M").
// Returns nil if valid, or an error describing the problem.
func ValidateDiskSize(size string) error {
	if len(size) < 2 {
		return fmt.Errorf("invalid disk size: %s", size)
	}

	suffix := size[len(size)-1]
	if suffix != 'K' && suffix != 'M' && suffix != 'G' && suffix != 'T' {
		return fmt.Errorf("disk size must end with K, M, G, or T: %s", size)
	}

	numPart := size[:len(size)-1]
	num, err := strconv.Atoi(numPart)
	if err != nil || num <= 0 {
		return fmt.Errorf("disk size must be a positive integer: %s", size)
	}

	switch suffix {
	case 'K', 'M':
		return fmt.Errorf("disk size must be at least 1G: %s", size)
	case 'T':
		if num > 10 {
			return fmt.Errorf("disk size must be at most 10T: %s", size)
		}
	case 'G':
		if num > 10240 {
			return fmt.Errorf("disk size must be at most 10T: %s", size)
		}
	}

	return nil
}

// SSH public key validation:
// - Must match standard OpenSSH public key format
// - Type must be a known algorithm (ssh-rsa, ssh-ed25519, ecdsa-sha2-*, ssh-dss)
// - Key data must be base64 encoded
// - Optional comment at the end
// - No newlines or control characters (prevents YAML injection in cloud-init)
var validSSHPubKeyRegex = regexp.MustCompile(`^(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/]+=*( [^\x00-\x1f\x7f]+)?$`)

// ValidateSSHPublicKey validates an SSH public key for safe use in cloud-init YAML.
// This prevents YAML injection attacks via malicious key content.
// Returns nil if valid, or an error describing the problem.
func ValidateSSHPublicKey(key string) error {
	if key == "" {
		return errors.New("SSH public key cannot be empty")
	}

	// Check for control characters (especially newlines which could inject YAML)
	for i, r := range key {
		if r < 32 || r == 127 {
			return fmt.Errorf("SSH public key contains invalid control character at position %d", i)
		}
	}

	// Validate the key format
	if !validSSHPubKeyRegex.MatchString(key) {
		return errors.New("invalid SSH public key format: must be 'type base64-key [comment]' (e.g., ssh-ed25519 AAAA... user@host)")
	}

	// Additional length check - SSH keys shouldn't be excessively long
	// RSA 4096-bit key is about 750 chars, allow generous margin
	if len(key) > 8192 {
		return fmt.Errorf("SSH public key too long (max 8192 characters, got %d)", len(key))
	}

	return nil
}

// Upstream DNS validation:
// - Must be in format host:port or just host (defaults to :53)
// - Host can be IPv4 address or hostname
var validHostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)

// NormalizeUpstreamDNS validates and normalizes an upstream DNS server address.
// Accepts formats like "8.8.8.8:53", "8.8.8.8", "dns.example.com:53", "dns.example.com".
// Returns the normalized address (always host:port, defaulting to port 53) or an error.
func NormalizeUpstreamDNS(upstream string) (string, error) {
	if upstream == "" {
		return "", errors.New("upstream DNS cannot be empty")
	}

	// Try to split host and port using net.SplitHostPort
	host, port, err := net.SplitHostPort(upstream)
	if err != nil {
		// net.SplitHostPort fails if there's no port, so treat the whole string as host
		host = upstream
		port = "53"
	}

	if host == "" {
		return "", fmt.Errorf("invalid upstream DNS format %q: host cannot be empty", upstream)
	}

	// Validate port
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return "", fmt.Errorf("invalid port %q in upstream DNS", port)
	}

	// Check if it looks like an IP address (contains only digits and dots)
	looksLikeIP := true
	for _, c := range host {
		if (c < '0' || c > '9') && c != '.' {
			looksLikeIP = false
			break
		}
	}

	if looksLikeIP {
		// Validate as IPv4 address using net.ParseIP
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() == nil {
			return "", fmt.Errorf("invalid IPv4 address %q in upstream DNS", host)
		}
	} else {
		// Validate as hostname
		if len(host) > 253 {
			return "", errors.New("hostname too long in upstream DNS")
		}
		if !validHostnameRegex.MatchString(host) {
			return "", fmt.Errorf("invalid upstream DNS format %q: must be host:port or host", upstream)
		}
	}

	return net.JoinHostPort(host, port), nil
}

// Log level and format identifiers. Mirrored in internal/logging; kept local
// here to avoid an import cycle.
const (
	logLevelDebug   = "debug"
	logLevelInfo    = "info"
	logLevelWarn    = "warn"
	logLevelWarning = "warning"
	logLevelError   = "error"
	logFormatText   = "text"
	logFormatJSON   = "json"
)

// validLogLevels contains the set of valid log level values.
var validLogLevels = map[string]bool{
	logLevelDebug:   true,
	logLevelInfo:    true,
	logLevelWarn:    true,
	logLevelWarning: true,
	logLevelError:   true,
}

// ValidateLogLevel validates a log level string.
// Valid values are "debug", "info", "warn", "warning", and "error".
// An empty string is valid and means "use default".
// Returns nil if valid, or an error describing the problem.
func ValidateLogLevel(level string) error {
	if level == "" {
		return nil // empty is valid (uses default)
	}
	if !validLogLevels[strings.ToLower(level)] {
		return fmt.Errorf("invalid log level %q: must be debug, info, warn, or error", level)
	}
	return nil
}

// validLogFormats contains the set of valid log format values.
var validLogFormats = map[string]bool{
	logFormatText: true,
	logFormatJSON: true,
}

// ValidateLogFormat validates a log format string.
// Valid values are "text" and "json".
// An empty string is valid and means "use default" (text).
// Returns nil if valid, or an error describing the problem.
func ValidateLogFormat(format string) error {
	if format == "" {
		return nil // empty is valid (uses default)
	}
	if !validLogFormats[strings.ToLower(format)] {
		return fmt.Errorf("invalid log format %q: must be text or json", format)
	}
	return nil
}

// validBackends contains the set of valid VM backend values.
// Currently only libvirt is implemented; other backends are planned for future.
var validBackends = map[string]bool{
	"libvirt": true,
}

// ValidateBackend validates a VM backend name.
// Currently only "libvirt" is supported.
// An empty string is valid and means "auto-detect".
// Returns nil if valid, or an error describing the problem.
func ValidateBackend(backend string) error {
	if backend == "" {
		return nil // empty is valid (auto-detect)
	}
	if !validBackends[strings.ToLower(backend)] {
		return fmt.Errorf("invalid backend %q: must be libvirt", backend)
	}
	return nil
}

// ValidateIPv4 validates that a string is a valid IPv4 address.
// Returns nil if valid, or an error describing the problem.
func ValidateIPv4(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return fmt.Errorf("invalid IPv4 address: %s", ip)
	}
	return nil
}

// ValidateYAMLSafeString ensures a string is safe to embed in YAML without escaping.
// Rejects control characters, colons at start, and other YAML metacharacters.
func ValidateYAMLSafeString(s, fieldName string) error {
	if s == "" {
		return nil // Empty is OK for optional fields
	}

	for i, r := range s {
		// Reject control characters (newlines, tabs, etc.)
		if r < 32 || r == 127 {
			return fmt.Errorf("%s contains invalid control character at position %d", fieldName, i)
		}
	}

	// Check for characters that could break YAML structure
	for _, dangerous := range []rune{':', '#', '&', '*', '!', '|', '>', '\'', '"', '%', '@', '`', '\\'} {
		for i, r := range s {
			if r == dangerous {
				return fmt.Errorf("%s contains invalid YAML character %q at position %d", fieldName, dangerous, i)
			}
		}
	}

	return nil
}

// tetragonVersionRegexp validates Tetragon version format.
// Valid formats: v1.0.0, v1.2.3, v1.0.0-rc1, v1.2.3-alpha, v1.3.0-rc.1
var tetragonVersionRegexp = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$`)

// ValidateTetragonVersion validates that a Tetragon version string is safe to use
// in shell commands and directory names. This provides defense-in-depth protection
// against command injection even though the ISO piggyback approach is used.
func ValidateTetragonVersion(version string) error {
	if version == "" {
		return nil // Empty is allowed when monitoring is disabled
	}
	if !tetragonVersionRegexp.MatchString(version) {
		return fmt.Errorf("invalid tetragon version format %q: must match v<major>.<minor>.<patch>[-<suffix>]", version)
	}
	return nil
}

// ValidatePEMCertificate validates that a string is a properly formatted PEM certificate.
// This prevents YAML injection attacks via malicious certificate content.
func ValidatePEMCertificate(certPEM string) error {
	block, rest := pem.Decode([]byte(certPEM))
	if block == nil {
		return errors.New("invalid PEM format: no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return fmt.Errorf("invalid PEM type: expected CERTIFICATE, got %s", block.Type)
	}
	// Check that the rest is either empty or another valid PEM block
	rest = bytes.TrimSpace(rest)
	if len(rest) > 0 {
		// Allow certificate chains
		for len(rest) > 0 {
			block, rest = pem.Decode(rest)
			if block == nil {
				return errors.New("invalid PEM format: trailing data after certificate")
			}
			if block.Type != "CERTIFICATE" {
				return fmt.Errorf("invalid PEM type in chain: expected CERTIFICATE, got %s", block.Type)
			}
			rest = bytes.TrimSpace(rest)
		}
	}
	return nil
}
