// Package config provides instance configuration management and path resolution.
package config

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"go.yaml.in/yaml/v3"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/validation"
)

// LibvirtImagesDir is the directory where libvirt can access disk images.
// This location is accessible by the libvirt-qemu user, unlike user home directories.
const LibvirtImagesDir = "/var/lib/libvirt/images/abox"

// Default values for new instances.
const (
	DefaultBase     = "ubuntu-24.04"
	DefaultDisk     = "20G"
	DefaultUpstream = "8.8.8.8:53"
)

// SSH usernames for supported distros.
const (
	defaultUser   = "ubuntu" // also used for unknown base images
	userAlmaLinux = "almalinux"
	userRocky     = "cloud-user"
	userCentOS    = "centos"
	userDebian    = "debian"
)

// lockFile holds the file descriptor for the global lock.
// Note: This global is safe because abox is a single-threaded CLI tool.
// Each command runs to completion before the next starts.
var lockFile File

// GenerateBridgeName creates a valid Linux bridge name (max 15 chars).
// Short names use "abox-<name>", long names use "ab-<hash>".
func GenerateBridgeName(instanceName string) string {
	if len("abox-"+instanceName) <= 15 {
		return "abox-" + instanceName
	}
	h := sha256.Sum256([]byte(instanceName))
	return fmt.Sprintf("ab-%x", h[:6]) // 3 + 12 = 15 chars
}

// AcquireLock acquires an exclusive lock on the abox data directory.
// This prevents race conditions during instance creation (port/subnet allocation).
// The lock is held until ReleaseLock is called.
func AcquireLock() error {
	if lockFile != nil {
		return errors.New("lock already held (missing ReleaseLock call)")
	}

	base, err := getBaseDir()
	if err != nil {
		return err
	}

	// Ensure base directory exists
	if err := fsys.MkdirAll(base, 0o700); err != nil {
		return fmt.Errorf("failed to create base directory: %w", err)
	}

	lockPath := filepath.Join(base, ".lock")
	f, err := fsys.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open lock file: %w", err)
	}

	// Acquire exclusive lock (blocks until available)
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return fmt.Errorf("failed to acquire lock: %w", err)
	}

	lockFile = f
	return nil
}

// ReleaseLock releases the exclusive lock on the abox data directory.
func ReleaseLock() error {
	if lockFile == nil {
		return nil
	}

	// Release the lock
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN); err != nil {
		lockFile.Close()
		lockFile = nil
		return fmt.Errorf("failed to release lock: %w", err)
	}

	err := lockFile.Close()
	lockFile = nil
	return err
}

// DNSConfig holds DNS-related configuration for an instance.
type DNSConfig struct {
	Port     int    `yaml:"port"`                // dnsfilter listen port
	Upstream string `yaml:"upstream"`            // upstream DNS server
	LogLevel string `yaml:"log_level,omitempty"` // "debug", "info", "warn", "error" (default: info)
}

// HTTPConfig holds HTTP proxy-related configuration for an instance.
type HTTPConfig struct {
	Port     int    `yaml:"port"`                // httpfilter proxy port
	LogLevel string `yaml:"log_level,omitempty"` // "debug", "info", "warn", "error" (default: info)
	MITM     bool   `yaml:"mitm"`                // Enable TLS MITM for domain fronting protection
}

// MonitorConfig holds monitoring-related configuration for an instance.
type MonitorConfig struct {
	Enabled     bool     `yaml:"enabled"`                // whether Tetragon monitoring is enabled
	Version     string   `yaml:"version,omitempty"`      // Tetragon version to use (empty = latest)
	KprobeMulti bool     `yaml:"kprobe_multi,omitempty"` // enable BPF kprobe_multi attachment
	Kprobes     []string `yaml:"kprobes,omitempty"`      // curated kprobe names (nil = all defaults)
	Policies    []string `yaml:"policies,omitempty"`     // absolute paths to custom TracingPolicy YAML files
}

// Instance represents an abox instance configuration.
type Instance struct {
	Version       int            `yaml:"version"`
	Name          string         `yaml:"name"`
	Backend       string         `yaml:"backend,omitempty"`        // VM backend (libvirt, proxmox, macos); auto-detected if empty
	BackendConfig map[string]any `yaml:"backend_config,omitempty"` // backend-specific overrides (each backend owns its keys)
	StorageDir    string         `yaml:"storage_dir,omitempty"`    // backend storage root for disk images; set at creation time
	CPUs          int            `yaml:"cpus"`
	Memory        int            `yaml:"memory"` // MB
	Base          string         `yaml:"base"`
	Subnet        string         `yaml:"subnet"`            // e.g., "10.10.10.0/24"
	Gateway       string         `yaml:"gateway"`           // e.g., "10.10.10.1"
	Bridge        string         `yaml:"bridge"`            // e.g., "abox-dev"
	DNS           DNSConfig      `yaml:"dns"`               // DNS filtering configuration
	HTTP          HTTPConfig     `yaml:"http,omitempty"`    // HTTP proxy filtering configuration
	Monitor       MonitorConfig  `yaml:"monitor,omitempty"` // Tetragon monitoring configuration
	Provision     []string       `yaml:"provision"`         // provision script paths
	SSHKey        string         `yaml:"ssh_key"`           // path to SSH private key
	User          string         `yaml:"user"`              // SSH username (default: ubuntu)
	Disk          string         `yaml:"disk"`              // e.g., "20G"
	MACAddress    string         `yaml:"mac_address"`       // VM MAC address
	IPAddress     string         `yaml:"ip_address"`        // assigned IP (DHCP or static)
}

// DefaultUserForBase returns the default SSH user for a given base image name.
// Mapping:
//   - almalinux-* -> "almalinux"
//   - rocky-* -> "cloud-user"
//   - centos-* -> "centos"
//   - debian-* -> "debian"
//   - ubuntu-* or unknown -> "ubuntu"
func DefaultUserForBase(base string) string {
	switch {
	case strings.HasPrefix(base, "almalinux-"):
		return userAlmaLinux
	case strings.HasPrefix(base, "rocky-"):
		return userRocky
	case strings.HasPrefix(base, "centos-"):
		return userCentOS
	case strings.HasPrefix(base, "debian-"):
		return userDebian
	default:
		return defaultUser
	}
}

// GetUser returns the SSH user for this instance.
// If User is set, returns that. Otherwise delegates to DefaultUserForBase.
func (i *Instance) GetUser() string {
	if i.User != "" {
		return i.User
	}
	return DefaultUserForBase(i.Base)
}

// GetBackend returns the backend for this instance.
// Returns empty string if the backend should be auto-detected.
func (i *Instance) GetBackend() string {
	return i.Backend
}

// Paths holds all paths for an instance.
type Paths struct {
	Base             string // ~/.local/share/abox
	Instances        string // ~/.local/share/abox/instances
	UserBaseImages   string // ~/.local/share/abox/base (user-writable, for downloads)
	BaseImages       string // <storage_dir>/base (backend-accessible)
	TetragonCache    string // ~/.local/share/abox/tetragon (user-writable, for Tetragon downloads)
	Instance         string // ~/.local/share/abox/instances/<name>
	Config           string // ~/.local/share/abox/instances/<name>/config.yaml
	Allowlist        string // ~/.local/share/abox/instances/<name>/allowlist.conf
	DiskDir          string // <storage_dir>/instances/<name>
	Disk             string // <storage_dir>/instances/<name>/disk.qcow2
	CloudInitISO     string // <storage_dir>/instances/<name>/cidata.iso
	SSHKey           string // ~/.local/share/abox/instances/<name>/id_ed25519
	KnownHosts       string // ~/.local/share/abox/instances/<name>/known_hosts
	CACert           string // ~/.local/share/abox/instances/<name>/ca-cert.pem (MITM CA)
	CAKey            string // ~/.local/share/abox/instances/<name>/ca-key.pem (MITM CA key)
	DNSSocket        string // DNS filter runtime socket path
	DNSPIDFile       string // dnsfilter PID file
	HTTPSocket       string // HTTP filter runtime socket path
	HTTPPIDFile      string // httpfilter PID file
	MonitorSocket    string // virtio-serial monitor socket path
	MonitorRPCSocket string // monitor daemon RPC socket path
	MonitorPIDFile   string // monitor daemon PID file

	// Logs directory (new structure)
	LogsDir            string // ~/.local/share/abox/instances/<name>/logs/
	DNSTrafficLog      string // logs/dns.log - DNS allow/block decisions
	HTTPTrafficLog     string // logs/http.log - HTTP allow/block decisions
	MonitorLog         string // logs/monitor.log - Tetragon events
	DNSServiceLog      string // logs/dns-service.log - DNS daemon stderr
	HTTPServiceLog     string // logs/http-service.log - HTTP daemon stderr
	MonitorServiceLog  string // logs/monitor-service.log - Monitor daemon stderr
	ProfileLog         string // logs/profile.log - domain capture (passive mode)
	PrivilegeHelperLog string // logs/privilege-helper.log - privilege helper
	KeyLog             string // logs/keys.log - TLS session keys (for abox tap)
}

// DefaultInstance returns a new instance with default values.
func DefaultInstance(name string) *Instance {
	return &Instance{
		Version: CurrentInstanceVersion,
		Name:    name,
		CPUs:    2,
		Memory:  4096,
		Base:    DefaultBase,
		DNS: DNSConfig{
			Upstream: DefaultUpstream,
		},
		HTTP: HTTPConfig{
			MITM: true, // Default to enabled for security
		},
		Disk: DefaultDisk,
	}
}

// GetPaths returns all paths for the given instance name.
// Uses LibvirtImagesDir as the default storage root for disk images.
// Use GetPathsWithStorage to specify a custom storage directory.
func GetPaths(name string) (*Paths, error) {
	return GetPathsWithStorage(name, "")
}

// GetPathsWithStorage returns all paths for the given instance name,
// using storageDir as the root for backend-managed disk images.
// If storageDir is empty, falls back to LibvirtImagesDir.
func GetPathsWithStorage(name, storageDir string) (*Paths, error) {
	if storageDir == "" {
		storageDir = LibvirtImagesDir
	}

	base, err := getBaseDir()
	if err != nil {
		return nil, err
	}

	instancesDir := filepath.Join(base, "instances")
	instanceDir := filepath.Join(instancesDir, name)

	// Path traversal protection: ensure the instance directory is still
	// under the instances directory after path cleaning
	cleanInstanceDir := filepath.Clean(instanceDir)
	cleanInstancesDir := filepath.Clean(instancesDir)

	// Check that the cleaned path is still under instances directory
	rel, err := filepath.Rel(cleanInstancesDir, cleanInstanceDir)
	if err != nil || rel == ".." || (len(rel) >= 3 && rel[:3] == "../") {
		return nil, errors.New("invalid instance name: path traversal detected")
	}

	// Runtime socket in XDG_RUNTIME_DIR (fall back to system temp for sockets)
	runtimeDir := RuntimeDirOr(os.TempDir())
	socketPath := filepath.Join(runtimeDir, fmt.Sprintf("abox-%s-dns.sock", name))

	// Disk images stored in backend-accessible location
	diskDir := filepath.Join(storageDir, "instances", name)

	// Logs directory under instance
	logsDir := filepath.Join(cleanInstanceDir, "logs")

	return &Paths{
		Base:             base,
		Instances:        instancesDir,
		UserBaseImages:   filepath.Join(base, "base"),
		BaseImages:       filepath.Join(storageDir, "base"),
		TetragonCache:    filepath.Join(base, "tetragon"),
		Instance:         cleanInstanceDir,
		Config:           filepath.Join(cleanInstanceDir, "config.yaml"),
		Allowlist:        filepath.Join(cleanInstanceDir, "allowlist.conf"),
		DiskDir:          diskDir,
		Disk:             filepath.Join(diskDir, "disk.qcow2"),
		CloudInitISO:     filepath.Join(diskDir, "cidata.iso"),
		SSHKey:           filepath.Join(cleanInstanceDir, "id_ed25519"),
		KnownHosts:       filepath.Join(cleanInstanceDir, "known_hosts"),
		CACert:           filepath.Join(cleanInstanceDir, "ca-cert.pem"),
		CAKey:            filepath.Join(cleanInstanceDir, "ca-key.pem"),
		DNSSocket:        socketPath,
		DNSPIDFile:       filepath.Join(runtimeDir, fmt.Sprintf("abox-%s-dns.pid", name)),
		HTTPSocket:       filepath.Join(runtimeDir, fmt.Sprintf("abox-%s-http.sock", name)),
		HTTPPIDFile:      filepath.Join(runtimeDir, fmt.Sprintf("abox-%s-http.pid", name)),
		MonitorSocket:    filepath.Join(cleanInstanceDir, "monitor.sock"),
		MonitorRPCSocket: filepath.Join(runtimeDir, fmt.Sprintf("abox-%s-monitor.sock", name)),
		MonitorPIDFile:   filepath.Join(runtimeDir, fmt.Sprintf("abox-%s-monitor.pid", name)),

		// Logs directory (new structure)
		LogsDir:            logsDir,
		DNSTrafficLog:      filepath.Join(logsDir, "dns.log"),
		HTTPTrafficLog:     filepath.Join(logsDir, "http.log"),
		MonitorLog:         filepath.Join(logsDir, "monitor.log"),
		DNSServiceLog:      filepath.Join(logsDir, "dns-service.log"),
		HTTPServiceLog:     filepath.Join(logsDir, "http-service.log"),
		MonitorServiceLog:  filepath.Join(logsDir, "monitor-service.log"),
		ProfileLog:         filepath.Join(logsDir, "profile.log"),
		PrivilegeHelperLog: filepath.Join(logsDir, "privilege-helper.log"),
		KeyLog:             filepath.Join(logsDir, "keys.log"),
	}, nil
}

// getBaseDir returns the base directory for abox data.
func getBaseDir() (string, error) {
	// Use XDG_DATA_HOME if set, otherwise ~/.local/share
	dataHome := fsys.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, err := fsys.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get home directory: %w", err)
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dataHome, "abox"), nil
}

// RuntimeDir returns the user's runtime directory for sockets and temp files.
// Uses XDG_RUNTIME_DIR if set, otherwise falls back to /run/user/<uid>.
// Returns an error if the directory doesn't exist.
func RuntimeDir() (string, error) {
	dir := fsys.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = fmt.Sprintf("/run/user/%d", os.Getuid())
	}
	if _, err := fsys.Stat(dir); os.IsNotExist(err) {
		return "", fmt.Errorf("runtime directory %s does not exist; ensure you are logged in or set XDG_RUNTIME_DIR", dir)
	}
	return dir, nil
}

// RuntimeDirOr returns the user's runtime directory, or the fallback if unavailable.
// This is useful when a fallback is acceptable (e.g., for sockets that can go elsewhere).
func RuntimeDirOr(fallback string) string {
	dir, err := RuntimeDir()
	if err != nil {
		return fallback
	}
	return dir
}

// EnsureDirs creates user-writable directories for an instance.
// Backend-specific storage directories (disk images, base images) are created
// by the backend's DiskManager during Create and EnsureBaseImage operations.
func EnsureDirs(paths *Paths) error {
	// User directories (0o700) - config, ssh keys, logs
	// These contain sensitive data like SSH keys and configs.
	userDirs := []string{
		paths.Instances,
		paths.Instance,
		paths.LogsDir, // logs subdirectory
	}
	for _, dir := range userDirs {
		if err := fsys.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// Load loads an instance configuration from disk.
// It validates security-sensitive fields to prevent injection attacks.
// If the instance has a StorageDir configured, disk paths are computed
// relative to that directory instead of the default LibvirtImagesDir.
func Load(name string) (*Instance, *Paths, error) {
	// First pass: load config to get the storage dir
	initialPaths, err := GetPaths(name)
	if err != nil {
		return nil, nil, err
	}

	logging.Debug("loading instance config", "path", initialPaths.Config)

	data, err := fsys.ReadFile(initialPaths.Config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config: %w", err)
	}

	var inst Instance
	if err := yaml.Unmarshal(data, &inst); err != nil {
		return nil, nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate config version
	if err := CheckVersion(inst.Version, CurrentInstanceVersion, "instance config"); err != nil {
		return nil, nil, err
	}

	// Validate security-sensitive fields to prevent injection attacks
	// from manually edited or corrupted config files
	if err := inst.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid config: %w", err)
	}

	// Recompute paths with the instance's storage dir if it differs from default
	paths := initialPaths
	if inst.StorageDir != "" && inst.StorageDir != LibvirtImagesDir {
		paths, err = GetPathsWithStorage(name, inst.StorageDir)
		if err != nil {
			return nil, nil, err
		}
	}

	return &inst, paths, nil
}

// Validate checks that the instance configuration is valid.
// This is called automatically by Load() to ensure configs loaded from disk
// are safe to use.
func (i *Instance) Validate() error {
	// Validate instance name
	if err := validation.ValidateInstanceName(i.Name); err != nil {
		return fmt.Errorf("invalid instance name: %w", err)
	}

	// Validate backend (if set, empty means auto-detect)
	if err := validation.ValidateBackend(i.Backend); err != nil {
		return fmt.Errorf("invalid backend: %w", err)
	}

	// Validate SSH user (if set, defaults are handled by GetUser)
	if i.User != "" {
		if err := validation.ValidateSSHUser(i.User); err != nil {
			return fmt.Errorf("invalid SSH user: %w", err)
		}
	}

	// Validate MAC address
	if i.MACAddress != "" {
		if err := validation.ValidateMACAddress(i.MACAddress); err != nil {
			return fmt.Errorf("invalid MAC address: %w", err)
		}
	}

	// Validate DNS log level
	if err := validation.ValidateLogLevel(i.DNS.LogLevel); err != nil {
		return fmt.Errorf("dns: %w", err)
	}

	// Validate HTTP log level
	if err := validation.ValidateLogLevel(i.HTTP.LogLevel); err != nil {
		return fmt.Errorf("http: %w", err)
	}

	// Validate resource limits
	if err := validation.ValidateResourceLimits(i.CPUs, i.Memory); err != nil {
		return err
	}

	// Validate disk size
	return validation.ValidateDiskSize(i.Disk)
}

// Save saves an instance configuration to disk.
func Save(inst *Instance, paths *Paths) error {
	logging.Debug("saving instance config", "path", paths.Config)

	data, err := yaml.Marshal(inst)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Use restrictive permissions (0o600) for config files since they
	// contain sensitive information like IP addresses, ports, and SSH key paths.
	if err := fsys.WriteFile(paths.Config, data, 0o600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// Exists checks if an instance exists.
func Exists(name string) bool {
	paths, err := GetPaths(name)
	if err != nil {
		return false
	}
	_, err = fsys.Stat(paths.Config)
	return err == nil
}

// List returns all instance names.
func List() ([]string, error) {
	paths, err := GetPaths("")
	if err != nil {
		return nil, err
	}

	entries, err := fsys.ReadDir(paths.Instances)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read instances directory: %w", err)
	}

	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			configPath := filepath.Join(paths.Instances, entry.Name(), "config.yaml")
			if _, err := fsys.Stat(configPath); err == nil {
				names = append(names, entry.Name())
			}
		}
	}
	return names, nil
}

// Delete removes an instance's configuration directory.
func Delete(name string) error {
	paths, err := GetPaths(name)
	if err != nil {
		return err
	}
	return fsys.RemoveAll(paths.Instance)
}

// AllocateSubnet finds the next available subnet for a new instance.
// If pool is empty, it uses the global config pool or the default "10.10.0.0/16".
func AllocateSubnet(pool string) (subnet, gateway string, thirdOctet int, err error) {
	if pool == "" {
		globalCfg, err := LoadGlobalConfig()
		if err != nil {
			logging.Debug("failed to load global config, using default subnet pool", "error", err)
			pool = "10.10.0.0/16"
		} else {
			pool = globalCfg.SubnetPool
		}
	}

	// Parse the pool to get the base network
	_, poolNet, err := net.ParseCIDR(pool)
	if err != nil {
		return "", "", 0, fmt.Errorf("invalid subnet pool %q: %w", pool, err)
	}

	// Extract base octets from pool
	poolIP := poolNet.IP.To4()
	if poolIP == nil {
		return "", "", 0, errors.New("IPv6 not supported")
	}

	instances, err := List()
	if err != nil {
		return "", "", 0, err
	}

	// Build map of used subnets
	usedSubnets := make(map[string]bool)
	for _, name := range instances {
		inst, _, err := Load(name)
		if err != nil {
			logging.Warn("skipping corrupted instance config during subnet allocation", "instance", name, "error", err)
			continue
		}
		usedSubnets[inst.Subnet] = true
	}

	// Try third octets starting from 10
	for i := 10; i < 255; i++ {
		candidateSubnet := fmt.Sprintf("%d.%d.%d.0/24", poolIP[0], poolIP[1], i)
		candidateGateway := fmt.Sprintf("%d.%d.%d.1", poolIP[0], poolIP[1], i)

		if !usedSubnets[candidateSubnet] {
			return candidateSubnet, candidateGateway, i, nil
		}
	}

	return "", "", 0, fmt.Errorf("no available subnets in pool %s", pool)
}

// ValidateSubnet validates a user-provided subnet and checks for conflicts.
// Returns the gateway IP and third octet if valid.
func ValidateSubnet(subnet string) (gateway string, thirdOctet int, err error) {
	// Parse the subnet
	ip, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", 0, fmt.Errorf("invalid subnet %q: %w", subnet, err)
	}

	// Must be a /24
	ones, _ := ipNet.Mask.Size()
	if ones != 24 {
		return "", 0, fmt.Errorf("subnet must be /24 (got /%d)", ones)
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return "", 0, errors.New("IPv6 not supported")
	}

	// Check the fourth octet is 0 (network address)
	if ipv4[3] != 0 {
		return "", 0, fmt.Errorf("subnet must end with .0 (got .%d)", ipv4[3])
	}

	// Check for conflicts with existing instances
	instances, err := List()
	if err != nil {
		return "", 0, err
	}

	for _, name := range instances {
		inst, _, err := Load(name)
		if err != nil {
			logging.Warn("skipping corrupted instance config during subnet validation", "instance", name, "error", err)
			continue
		}
		if inst.Subnet == subnet {
			return "", 0, fmt.Errorf("subnet %s is already used by instance %q", subnet, name)
		}
	}

	gateway = fmt.Sprintf("%d.%d.%d.1", ipv4[0], ipv4[1], ipv4[2])
	thirdOctet = int(ipv4[2])

	return gateway, thirdOctet, nil
}
