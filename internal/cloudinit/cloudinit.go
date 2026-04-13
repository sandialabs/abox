// Package cloudinit provides cloud-init ISO generation for VM bootstrap.
package cloudinit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/sandialabs/abox/internal/errhint"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/validation"
)

// Config holds the configuration for cloud-init.
type Config struct {
	InstanceID   string
	Hostname     string
	Username     string
	SSHPublicKey string
	MACAddress   string // VM MAC address for network-config matching
	Contributors []Contributor
}

// GenerateMetaData generates the meta-data YAML content.
func GenerateMetaData(cfg *Config) ([]byte, error) {
	// Validate inputs to prevent YAML injection
	// InstanceID and Hostname must not contain YAML metacharacters
	if err := validation.ValidateYAMLSafeString(cfg.InstanceID, "instance-id"); err != nil {
		return nil, err
	}
	if err := validation.ValidateYAMLSafeString(cfg.Hostname, "hostname"); err != nil {
		return nil, err
	}

	content := fmt.Sprintf(`instance-id: %s
local-hostname: %s
`, cfg.InstanceID, cfg.Hostname)
	return []byte(content), nil
}

// GenerateNetworkConfig generates network-config for the cloud-init NoCloud ISO.
//
// We use network-config version 1, not version 2. Version 1 is maintained for
// general compatibility across all cloud-init renderers (ENI, networkd, netplan,
// NetworkManager) and all supported distros. The mac_address field on a
// "physical" device type causes cloud-init to scan /sys/class/net/*/address,
// resolve the MAC to the real kernel interface, and generate correct config.
//
// v1 is not deprecated as of cloud-init 25.3 (checked Feb 2026).
//
// Historical context: Debian 11/12 are no longer offered as base images (their
// cloud images have broken network initialization under libvirt/QEMU), but v2
// network-config was also broken on those versions. Debian 11 (cloud-init 20.4)
// and Debian 12 (cloud-init 23.1) used the ENI (ifupdown) renderer, which had
// broken support for v2 match blocks — MAC address matching, name globs, and
// set-name all failed because the renderer used YAML map keys literally as
// interface names instead of resolving them.
// See also: Debian bug #965122 (cloud-init ENI renderer v2 match issues).
func GenerateNetworkConfig(cfg *Config) ([]byte, error) {
	if cfg.MACAddress == "" {
		return nil, nil
	}
	if err := validation.ValidateMACAddress(cfg.MACAddress); err != nil {
		return nil, fmt.Errorf("invalid MAC address for network-config: %w", err)
	}
	content := fmt.Sprintf(`version: 1
config:
  - type: physical
    name: id0
    mac_address: "%s"
    subnets:
      - type: dhcp
`, cfg.MACAddress)
	return []byte(content), nil
}

// assembledOutput holds the combined cloud-init output from all contributors.
type assembledOutput struct {
	userData []byte
	isoFiles map[string]string
}

// assemble generates user-data and collects ISO files from all contributors.
func assemble(cfg *Config) (*assembledOutput, error) {
	// Validate all inputs to prevent YAML injection attacks
	if err := validation.ValidateYAMLSafeString(cfg.Hostname, "hostname"); err != nil {
		return nil, err
	}

	// Username validation - must be safe for YAML and shell
	if err := validation.ValidateSSHUser(cfg.Username); err != nil {
		return nil, fmt.Errorf("invalid username for cloud-init: %w", err)
	}

	// SSH public key validation - critical for security
	// A malicious key could inject arbitrary cloud-init commands
	if err := validation.ValidateSSHPublicKey(cfg.SSHPublicKey); err != nil {
		return nil, fmt.Errorf("invalid SSH public key for cloud-init: %w", err)
	}

	var content strings.Builder
	fmt.Fprintf(&content, `#cloud-config
hostname: %s
manage_etc_hosts: true
users:
  - name: %s
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - %s
ssh_pwauth: false
disable_root: true
ssh_deletekeys: false
`, cfg.Hostname, cfg.Username, cfg.SSHPublicKey)

	// Collect contributions from all contributors
	var allContributions []*Contribution
	isoFiles := make(map[string]string)

	for _, contributor := range cfg.Contributors {
		contrib, err := contributor.Contribute()
		if err != nil {
			return nil, err
		}
		if contrib == nil {
			continue
		}
		allContributions = append(allContributions, contrib)
		for k, v := range contrib.ISOFiles {
			if _, exists := isoFiles[k]; exists {
				return nil, fmt.Errorf("ISO file conflict: multiple contributors provide %q", k)
			}
			isoFiles[k] = v
		}
	}

	// Append bootcmd sections from contributors
	for _, contrib := range allContributions {
		if contrib.Bootcmd != "" {
			content.WriteString(contrib.Bootcmd)
		}
	}

	// Collect all write_files entries
	var writeFilesEntries []string
	for _, contrib := range allContributions {
		writeFilesEntries = append(writeFilesEntries, contrib.WriteFiles...)
	}

	// Add write_files section if we have any entries
	if len(writeFilesEntries) > 0 {
		content.WriteString("write_files:\n")
		content.WriteString(strings.Join(writeFilesEntries, "\n"))
		content.WriteString("\n")
	}

	// Collect all runcmd entries
	var runcmdEntries []string
	for _, contrib := range allContributions {
		runcmdEntries = append(runcmdEntries, contrib.Runcmd...)
	}

	// Add runcmd section if we have any entries
	if len(runcmdEntries) > 0 {
		content.WriteString("runcmd:\n")
		content.WriteString(strings.Join(runcmdEntries, "\n"))
		content.WriteString("\n")
	}

	return &assembledOutput{
		userData: []byte(content.String()),
		isoFiles: isoFiles,
	}, nil
}

// GenerateUserData generates the user-data cloud-config YAML content.
func GenerateUserData(cfg *Config) ([]byte, error) {
	out, err := assemble(cfg)
	if err != nil {
		return nil, err
	}
	return out.userData, nil
}

// IndentLines adds 6 spaces to the beginning of each non-empty line (for cloud-init YAML).
func IndentLines(s string) string {
	const indent = "      " // 6 spaces for cloud-init content indentation
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = indent + line
		}
	}
	return strings.Join(lines, "\n")
}

// RenderTemplate parses and executes a template with the given data.
func RenderTemplate(name, tmpl string, data any) (string, error) {
	t, err := template.New(name).Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse %s template: %w", name, err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to render %s template: %w", name, err)
	}
	return buf.String(), nil
}

// FindISOTool finds an available ISO creation tool.
// Returns the path to genisoimage or xorriso, or an error if neither is found.
func FindISOTool() (string, error) {
	// Try genisoimage first (more common on Debian/Ubuntu)
	if path, err := exec.LookPath("genisoimage"); err == nil {
		return path, nil
	}

	// Try xorriso as fallback
	if path, err := exec.LookPath("xorriso"); err == nil {
		return path, nil
	}

	return "", &errhint.ErrHint{
		Err:  errors.New("no ISO creation tool found"),
		Hint: "Install genisoimage or xorriso",
	}
}

// CreateISO creates a cloud-init NoCloud ISO at the specified path.
func CreateISO(outputPath string, cfg *Config) error {
	isoTool, err := FindISOTool()
	if err != nil {
		return err
	}

	// Create a temporary directory for the ISO contents
	tempDir, err := os.MkdirTemp("", "cloudinit-")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate instance ID if not provided
	if cfg.InstanceID == "" {
		cfg.InstanceID = fmt.Sprintf("abox-%s-%d", cfg.Hostname, time.Now().Unix())
	}

	// Generate meta-data
	metaData, err := GenerateMetaData(cfg)
	if err != nil {
		return fmt.Errorf("failed to generate meta-data: %w", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "meta-data"), metaData, 0o644); err != nil { //nolint:gosec // cloud-init requires readable files
		return fmt.Errorf("failed to write meta-data: %w", err)
	}

	// Generate network-config (needed for reliable first-boot DHCP)
	networkConfig, err := GenerateNetworkConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to generate network-config: %w", err)
	}
	if networkConfig != nil {
		if err := os.WriteFile(filepath.Join(tempDir, "network-config"), networkConfig, 0o644); err != nil { //nolint:gosec // cloud-init requires readable files
			return fmt.Errorf("failed to write network-config: %w", err)
		}
	}

	// Assemble user-data and collect ISO files from contributors
	assembled, err := assemble(cfg)
	if err != nil {
		return fmt.Errorf("failed to generate user-data: %w", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "user-data"), assembled.userData, 0o644); err != nil { //nolint:gosec // cloud-init requires readable files
		return fmt.Errorf("failed to write user-data: %w", err)
	}

	// Copy ISO files from contributors (e.g., Tetragon tarball)
	for dstName, srcPath := range assembled.isoFiles {
		if srcPath == "" {
			continue
		}
		if err := copyFile(srcPath, filepath.Join(tempDir, dstName)); err != nil {
			return fmt.Errorf("failed to copy %s to ISO: %w", dstName, err)
		}
		logging.Debug("added file to ISO", "name", dstName, "source", srcPath)
	}

	// Build the ISO
	logging.Debug("generating cloud-init ISO", "tool", isoTool, "path", outputPath)
	var cmd *exec.Cmd
	if filepath.Base(isoTool) == "xorriso" {
		// xorriso syntax for creating ISO
		cmd = exec.Command(isoTool,
			"-as", "genisoimage",
			"-output", outputPath,
			"-volid", "cidata",
			"-joliet",
			"-rock",
			tempDir,
		)
	} else {
		// genisoimage syntax
		cmd = exec.Command(isoTool,
			"-output", outputPath,
			"-volid", "cidata",
			"-joliet",
			"-rock",
			tempDir,
		)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create ISO: %s: %w", string(output), err)
	}

	return nil
}

// copyFile copies a file from src to dst.
// It refuses to copy symlinks to prevent path traversal attacks.
func copyFile(src, dst string) error {
	// Check for symlinks to prevent path traversal attacks
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to copy symlink: %s", src)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to copy non-regular file: %s", src)
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}

	if _, err = io.Copy(dstFile, srcFile); err != nil {
		dstFile.Close()
		return err
	}
	return dstFile.Close()
}
