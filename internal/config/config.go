// Package config provides instance configuration management and path resolution.
package config

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/sandialabs/abox/internal/allowlist"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/sysutil"
	"github.com/sandialabs/abox/internal/validation"
)

// LibvirtImagesDir is the shared parent for abox's libvirt disk storage. Each
// user gets a per-uid subtree beneath it (see LibvirtStorageDir); the old
// monolithic root-owned layout directly under this path is treated as legacy
// (see IsLegacyStorage).
const LibvirtImagesDir = "/var/lib/libvirt/images/abox"

// LibvirtStorageDir returns the calling user's per-user disk storage root:
// <LibvirtImagesDir>/<uid>. It lives outside $HOME so the QEMU runtime process
// (libvirt-qemu) can reach the images WITHOUT any ACLs on the user's home
// directory: the privilege helper creates this root owned by the user and setgid
// to the QEMU group, so every image created underneath inherits that group and
// is readable by the VM process via group membership (see the helper's
// EnsureStorageRoot). It is keyed on the NUMERIC uid — not the username — so the
// client and the helper (which derives it from the socket peer uid) compute the
// identical path with no username lookup.
func LibvirtStorageDir() string {
	return filepath.Join(LibvirtImagesDir, strconv.Itoa(os.Getuid()))
}

// UserStorageDir returns the $HOME-based storage root (<base>/disks). It is
// retained for migration/compatibility comparisons and for backends whose VM
// process runs as the calling user (so $HOME is reachable without a separate
// runtime user); the libvirt backend uses LibvirtStorageDir instead.
func UserStorageDir() string {
	base, err := getBaseDir()
	if err != nil {
		// Its callers (vfkit/vmware) run the VM as the calling user, so falling back
		// to the Linux root-owned LibvirtImagesDir would be both wrong-platform and
		// unwritable. Degrade to a per-user temp path (writable by this user) and
		// warn, rather than returning a path the caller cannot use.
		logging.Warn("could not determine home directory for storage root; using a temporary location", "error", err)
		return filepath.Join(os.TempDir(), "abox", "disks")
	}
	return filepath.Join(base, "disks")
}

// Default values for new instances.
const (
	DefaultBase = "ubuntu-24.04"
	DefaultDisk = "20G"
	// DefaultUpstream is empty, meaning "use the host's system resolver" (read
	// from /etc/resolv.conf in dnsfilter.NewServer). A hardcoded public resolver
	// like 8.8.8.8 fails on networks where it is unreachable (air-gapped or
	// egress-filtered environments, and our e2e host). An explicit upstream still
	// overrides.
	DefaultUpstream = ""

	// DefaultHTTPMaxConnections caps concurrent client connections to the HTTP
	// filter proxy, bounding host fd/goroutine use against a hostile VM. A
	// zero/unset value in a saved config resolves to this default at startup.
	DefaultHTTPMaxConnections = 512
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
	if err := lockFileExclusive(f.Fd()); err != nil {
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
	if err := unlockFile(lockFile.Fd()); err != nil {
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
	Port           int    `yaml:"port"`                      // httpfilter proxy port
	LogLevel       string `yaml:"log_level,omitempty"`       // "debug", "info", "warn", "error" (default: info)
	MITM           bool   `yaml:"mitm"`                      // Enable TLS MITM for domain fronting protection
	MaxConnections int    `yaml:"max_connections,omitempty"` // cap on concurrent client connections (0/unset = DefaultHTTPMaxConnections)
	// AllowPrivateTargets is an opt-in list of CIDRs the DNS/HTTP filters may
	// reach despite the default SSRF deny of loopback/private/link-local/metadata
	// ranges. Empty = deny all such targets. Shared by both filters.
	AllowPrivateTargets []string `yaml:"allow_private_targets,omitempty"`
	// SecretInjections maps host-side secret values into outbound request headers
	// so the guest never holds the raw credential. Each binding references a key in
	// the per-instance secret store; only the non-sensitive mapping lives here.
	SecretInjections []SecretInjection `yaml:"secret_injections,omitempty"`
}

// SecretInjection binds a stored secret value to an outbound request header for a
// specific host. The value itself lives in the secret store (keyed by Key), never
// in config. Injection happens only on MITM-intercepted HTTPS requests whose path
// matches PathPrefix (empty = all paths).
type SecretInjection struct {
	Key         string `yaml:"key"`                    // secret store key holding the value
	Host        string `yaml:"host"`                   // exact host to inject into (e.g. api.anthropic.com)
	Header      string `yaml:"header"`                 // header name to set (e.g. x-api-key, Authorization)
	PathPrefix  string `yaml:"path_prefix,omitempty"`  // only inject when the request path matches this prefix
	ValuePrefix string `yaml:"value_prefix,omitempty"` // prepended to the value (e.g. "Bearer ")
}

// ValidateSecretInjections validates a set of secret-injection bindings. Shared by
// Instance.Validate (guards hand-edited config.yaml) and boxfile.Validate.
func ValidateSecretInjections(injections []SecretInjection) error {
	seen := make(map[string]struct{}, len(injections))
	for i, inj := range injections {
		if err := validation.ValidateSecretKey(inj.Key); err != nil {
			return fmt.Errorf("secret_injections[%d]: %w", i, err)
		}
		// Injection matches an exact host; a wildcard entry would pass
		// ValidateDomain but never match at runtime (canonicalization does not
		// expand "*."), silently disabling the binding — reject it explicitly.
		if strings.HasPrefix(inj.Host, "*.") {
			return fmt.Errorf("secret_injections[%d]: host must be an exact host, not a wildcard (%q)", i, inj.Host)
		}
		if err := validation.ValidateDomain(inj.Host); err != nil {
			return fmt.Errorf("secret_injections[%d]: invalid host: %w", i, err)
		}
		if err := validation.ValidateHTTPHeaderName(inj.Header); err != nil {
			return fmt.Errorf("secret_injections[%d]: %w", i, err)
		}
		if err := validation.ValidateHTTPHeaderValue(inj.ValuePrefix); err != nil {
			return fmt.Errorf("secret_injections[%d]: value_prefix: %w", i, err)
		}
		if inj.PathPrefix != "" && !strings.HasPrefix(inj.PathPrefix, "/") {
			return fmt.Errorf("secret_injections[%d]: path_prefix must start with %q", i, "/")
		}
		// Reject duplicate host+header so injection rule ordering is never
		// significant (the proxy would otherwise clobber one with the other).
		// Dedupe on the SAME canonical host form the runtime injection map uses
		// (lowercase + punycode), so IDN-equivalent hosts can't slip past here
		// yet collide at inject time.
		dedupe := allowlist.NormalizeDomain(inj.Host) + "\x00" + strings.ToLower(inj.Header)
		if _, dup := seen[dedupe]; dup {
			return fmt.Errorf("secret_injections[%d]: duplicate host+header (%s, %s)", i, inj.Host, inj.Header)
		}
		seen[dedupe] = struct{}{}
	}
	return nil
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
	Secrets          string // ~/.local/share/abox/instances/<name>/secrets (host-only secret store)
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
	VMNetSocket      string // <Instance>/run/vmnet.sock (macOS vfkit: vmnet-helper's bound datagram socket)

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
			MITM:           true, // Default to enabled for security
			MaxConnections: DefaultHTTPMaxConnections,
		},
		Disk: DefaultDisk,
	}
}

// GetPaths returns all paths for the given instance name.
// Uses the user-owned default storage root (<base>/disks) for disk images.
// Use GetPathsWithStorage to specify a custom storage directory.
func GetPaths(name string) (*Paths, error) {
	return GetPathsWithStorage(name, "")
}

// GetPathsWithStorage returns all paths for the given instance name,
// using storageDir as the root for backend-managed disk images.
// If storageDir is empty, defaults to the user-owned <base>/disks.
func GetPathsWithStorage(name, storageDir string) (*Paths, error) {
	base, err := getBaseDir()
	if err != nil {
		return nil, err
	}

	if storageDir == "" {
		storageDir = filepath.Join(base, "disks")
	} else if err := validateStorageDir(storageDir); err != nil {
		// Defense-in-depth: storageDir flows into disk paths used for os.RemoveAll
		// and qemu-img output. Load validates it, but guard direct callers too.
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
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
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
		Secrets:          filepath.Join(cleanInstanceDir, "secrets"),
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
		VMNetSocket:      filepath.Join(cleanInstanceDir, "run", "vmnet.sock"),

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

// ValidateSocketPaths checks that every unix-domain socket path abox will bind
// for an instance fits within the platform's sun_path limit. It is enforced only
// on macOS (103-byte cap; see socketpath_darwin.go) — off macOS it is a no-op
// (see socketpath_other.go for the rationale and the known long-XDG_RUNTIME_DIR
// limitation). On macOS a long instance name under the lengthy $TMPDIR runtime
// dir can overflow the cap and make net.Listen("unix", …) fail with an opaque
// "invalid argument"; catching it at create/import time yields an actionable
// "use a shorter name" error instead.
func ValidateSocketPaths(paths *Paths) error {
	if maxUnixSocketPathLen <= 0 || paths == nil {
		return nil
	}
	sockets := map[string]string{
		"DNS filter":  paths.DNSSocket,
		"HTTP filter": paths.HTTPSocket,
		"monitor RPC": paths.MonitorRPCSocket,
		"monitor":     paths.MonitorSocket,
		"vmnet":       paths.VMNetSocket,
	}
	for label, p := range sockets {
		if len(p) > maxUnixSocketPathLen {
			return fmt.Errorf(
				"%s socket path is too long for this platform (%d > %d bytes): %s"+
					" (use a shorter instance name — the name is part of the socket path)",
				label, len(p), maxUnixSocketPathLen, p)
		}
	}
	return nil
}

// Base-image on-disk extensions. The format is fixed per-platform (see
// UserBaseImageExt), so these name the two possibilities rather than a free set.
const (
	extQcow2 = ".qcow2" // Linux (libvirt/KVM)
	extRaw   = ".raw"   // macOS (vfkit)
)

// UserBaseImageExt returns the file extension (including the leading dot) for
// base images on this host. The same extension applies to both the user cache
// (paths.UserBaseImages) and the backend storage dir (paths.BaseImages) because
// the backend disk format is fixed per-platform:
//   - Linux (libvirt/KVM): ".qcow2"
//   - macOS (vfkit):       ".raw" (Apple Virtualization.framework cannot read qcow2)
//
// `abox base pull` produces files with this extension, backends clone/copy using
// the same extension, and callers that look up base images by name (list, remove,
// prune, EnsureBaseImage) should all use this helper.
func UserBaseImageExt() string {
	if runtime.GOOS == "darwin" {
		return extRaw
	}
	return extQcow2
}

// UserBaseImageName returns the canonical base image filename for this host
// (e.g., "ubuntu-24.04.raw" on macOS, "ubuntu-24.04.qcow2" on Linux). Applies to
// both user cache and backend storage — see UserBaseImageExt.
func UserBaseImageName(base string) string {
	return base + UserBaseImageExt()
}

// BaseImageExts returns every on-disk base-image extension to probe when looking
// up a base image by name, with this host's native extension first. Callers that
// only construct a path use UserBaseImageName; callers that must *discover* an
// existing base (and may encounter one written for another backend/platform)
// should probe all of these. Mirrors baseImageExts in e2e/helpers_test.go.
func BaseImageExts() []string {
	if UserBaseImageExt() == extRaw {
		return []string{extRaw, extQcow2}
	}
	return []string{extQcow2, extRaw}
}

// RuntimeDir returns the user's runtime directory for sockets and temp files.
// Uses XDG_RUNTIME_DIR if set, otherwise falls back to /run/user/<uid>.
// Returns an error if the directory doesn't exist.
func RuntimeDir() (string, error) {
	dir := fsys.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = fmt.Sprintf("/run/user/%d", os.Getuid())
	}
	// Normalize after the empty-string fallback: some environments (e.g. WSL)
	// set XDG_RUNTIME_DIR with a trailing slash, which would otherwise produce
	// unclean paths downstream. Clean must run after the fallback since
	// filepath.Clean("") returns ".".
	dir = filepath.Clean(dir)
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

// SecureRuntimeDir returns the platform's per-user secure runtime directory for
// hosting the privilege-helper socket, after asserting it is safe to use.
//
// Resolution is platform-specific via the runtimeDirFallback seam:
//   - linux: XDG_RUNTIME_DIR if set, otherwise /run/user/<uid>.
//   - darwin: $TMPDIR (os.TempDir()); macOS has no XDG_RUNTIME_DIR or
//     /run/user/<uid>, and $TMPDIR is a per-user 0700 directory.
//
// The chosen directory is then validated to be an existing directory that is
// owned by the invoking user and not writable by group or other. This refuses
// world-writable locations such as a shared /tmp, where another user could
// pre-create or hijack the helper socket. The linux resolution order (XDG then
// /run/user then error) is preserved.
//
// The result is always filepath.Clean'd. This matters on macOS, where launchd
// exports TMPDIR with a trailing slash ("/var/folders/.../T/"): callers join a
// filename onto this directory to form the privilege-helper socket path, and the
// helper rejects a non-clean --socket argument (see privilege.ValidateSocketPath),
// so an uncleaned dir makes every helper spawn exit non-zero.
func SecureRuntimeDir() (string, error) {
	dir := fsys.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = runtimeDirFallback()
	}
	dir = filepath.Clean(dir)
	if err := assertSecureRuntimeDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

// assertSecureRuntimeDir verifies dir exists, is a directory, is owned by the
// invoking UID, and is not group/other-writable. It is the shared guard used by
// the helper socket spawn and external-socket validation paths so a
// world-writable directory (e.g. /tmp) is refused with a clear error.
func assertSecureRuntimeDir(dir string) error {
	info, err := fsys.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("secure runtime directory %s does not exist; ensure you are logged in or set XDG_RUNTIME_DIR", dir)
		}
		return fmt.Errorf("stat secure runtime directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("secure runtime directory %s is not a directory", dir)
	}
	// Reject group- or other-writable directories: only the owner may be able to
	// create the helper socket there.
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("secure runtime directory %s is group/other-writable (mode %o); refusing to use it for the privilege helper socket", dir, info.Mode().Perm())
	}
	// Ownership check: the directory must belong to the invoking user. FileOwner
	// reports ok=false where ownership cannot be determined; treat that as a
	// failure (fail closed) rather than trusting an unowned directory.
	uidOwner, _, ok := sysutil.FileOwner(info)
	if !ok {
		return fmt.Errorf("cannot determine owner of secure runtime directory %s (ownership checks unsupported on this platform)", dir)
	}
	if uidOwner != os.Getuid() {
		return fmt.Errorf("secure runtime directory %s is not owned by the current user (uid %d)", dir, os.Getuid())
	}
	return nil
}

// EnsureDirs creates user-writable directories for an instance.
// Backend-specific storage directories (disk images, base images) are created
// by the backend's DiskManager during Create and EnsureBaseImage operations.
func EnsureDirs(paths *Paths) error {
	// Fail fast if the instance's socket paths would overflow the platform's
	// unix sun_path limit (macOS + long instance name); a no-op elsewhere. This
	// is the shared chokepoint for instance creation (create + import), so a
	// long-named instance can never be provisioned only to fail later at bind
	// time with an opaque "invalid argument".
	if err := ValidateSocketPaths(paths); err != nil {
		return err
	}

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

	// Recompute paths with the instance's persisted storage dir. Any non-empty
	// value is honored, including the legacy root-owned LibvirtImagesDir that
	// pre-upgrade instances persisted: their disk still lives there, so resolving
	// to it (rather than silently falling back to the new <base>/disks default,
	// where no disk exists) keeps start/stop/remove/export operating on the real
	// image instead of orphaning it.
	paths := initialPaths
	if inst.StorageDir != "" {
		// Normalize so every consumer (path construction, IsLegacyStorage) sees a
		// canonical value regardless of benign forms (trailing slash) on disk.
		inst.StorageDir = filepath.Clean(inst.StorageDir)
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

	// The backend name is intentionally not validated here: it is only ever used
	// as a registry key, and backend.Get (via factory.BackendFor) rejects unknown
	// or unavailable backends at resolution time with a clear error. Validating it
	// here would require config -> backend, which cycles (backend -> config).

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

	// Validate HTTP max connections (0 = unset, resolved to the default at startup).
	if i.HTTP.MaxConnections < 0 {
		return fmt.Errorf("http: max_connections must be >= 0 (got %d)", i.HTTP.MaxConnections)
	}

	// Validate allow_private_targets CIDR syntax so a hand-edited config.yaml fails
	// at Load rather than only when the daemon starts (mirrors boxfile.Validate,
	// which uses filterbase.NewTargetChecker). We only check syntax here — config
	// cannot import filterbase (filterbase imports config), so the full policy
	// check (e.g. rejecting a default-route CIDR) still happens at daemon start via
	// filterbase.NewTargetChecker.
	for _, cidr := range i.HTTP.AllowPrivateTargets {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("http: invalid allow_private_targets CIDR %q: %w", cidr, err)
		}
	}

	// Validate secret-injection bindings so a hand-edited config.yaml fails at
	// Load rather than only when the daemon starts.
	if err := ValidateSecretInjections(i.HTTP.SecretInjections); err != nil {
		return fmt.Errorf("http: %w", err)
	}

	// Note: DNS/HTTP filter ports are NOT range-validated here. They are normally
	// auto-allocated (0 in config) and the privileged helper bounds them at Apply
	// time; validating here would make a config with an out-of-range port fail to
	// Load at all, which would also break read-only/teardown commands (stop,
	// remove, status) for that instance.

	// Validate the persisted storage dir (user-editable in config.yaml). It must
	// be an absolute, traversal-free path: it is joined into disk paths that flow
	// to os.RemoveAll (Delete) and qemu-img output.
	if err := validateStorageDir(i.StorageDir); err != nil {
		return err
	}

	// Validate resource limits
	if err := validation.ValidateResourceLimits(i.CPUs, i.Memory); err != nil {
		return err
	}

	// Validate disk size
	return validation.ValidateDiskSize(i.Disk)
}

// IsLegacyStorage reports whether an instance's disk storage predates the
// group-owned per-user storage model and cannot be managed by it: the old
// monolithic root-owned layout directly under LibvirtImagesDir (shared across
// users, no per-uid subdir). Such instances must be migrated with `abox migrate`
// first. The current default — a per-user subdir LibvirtImagesDir/<uid>, which
// shares the LibvirtImagesDir prefix — is explicitly NOT legacy.
func IsLegacyStorage(inst *Instance, paths *Paths) bool {
	perUser := LibvirtStorageDir()
	if inst.StorageDir == perUser || strings.HasPrefix(paths.Disk, perUser+string(filepath.Separator)) {
		return false
	}
	return inst.StorageDir == LibvirtImagesDir || strings.HasPrefix(paths.Disk, LibvirtImagesDir+string(filepath.Separator))
}

// validateStorageDir rejects a storage dir that is relative or escapes via "..".
// An empty value (the common case) is fine — it resolves to the default later.
//
// Benign non-canonical forms (a trailing slash, "." segments) are tolerated:
// they do not change the target directory and are normalized at load time. We do
// not reject them, because that would make the whole instance fail to Load and
// break read-only/teardown commands (stop, remove, status) for it too.
func validateStorageDir(dir string) error {
	if dir == "" {
		return nil
	}
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("storage_dir must be an absolute path (got %q)", dir)
	}
	if slices.Contains(strings.Split(dir, string(filepath.Separator)), "..") {
		return fmt.Errorf("storage_dir must not contain '..' path traversal (got %q)", dir)
	}
	return nil
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

// DeriveHostIP derives the guest's IP address from its gateway by replacing the
// host octet with .10 (gateway "10.10.20.1" -> "10.10.20.10", "192.168.128.1"
// -> "192.168.128.10"). Used to seed Instance.IPAddress, which serves as the
// certificate SAN and the fallback IP when the backend can't report a live one.
//
// A malformed or non-IPv4 gateway returns "" rather than a silently wrong address
// like "0.0.0.10" — the .10 convention is load-bearing (pf subnet-keying, nwfilter
// gateway rules), so a bad derivation must be visible (callers/GenerateNetworkConfig
// reject an empty IP) instead of plausible-but-wrong.
func DeriveHostIP(gateway string) string {
	ip := net.ParseIP(gateway)
	if ip == nil {
		return ""
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.10", ip4[0], ip4[1], ip4[2])
}

// routeProbe reports whether the host already routes the subnet whose gateway is
// gatewayIP. It defaults to a no-op so unit tests never shell out to `ip`/`route`;
// the real binary wires the platform prober via SetRouteProbe in main. See
// RouteConflicts.
var routeProbe = func(gatewayIP string) bool { return false }

// SetRouteProbe installs the host-route prober used by subnet allocation to skip
// /24s the host already routes elsewhere (e.g. a VPN). Called once from the abox
// binary's main; left as a no-op under test.
func SetRouteProbe(f func(gatewayIP string) bool) { routeProbe = f }

// RouteConflicts reports whether the host already has a route covering the /24
// whose gateway is gatewayIP. It is the exported entry point backends use during
// allocation (vfkit) and the create command uses to warn about an explicit
// --subnet that collides with a host route. No-op (false) unless SetRouteProbe
// has installed a real prober.
func RouteConflicts(gatewayIP string) bool { return routeProbe(gatewayIP) }

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

	usedSubnets, err := UsedInstanceSubnets()
	if err != nil {
		return "", "", 0, err
	}

	// Try third octets starting from 10. Skip subnets already claimed by another
	// instance (checked first, so claimed subnets cost zero route probes) and, via
	// the fail-open host-route probe, any /24 the host already routes elsewhere
	// (e.g. a VPN split-include) so the guest stays reachable from the host.
	for i := 10; i < 255; i++ {
		candidateSubnet := fmt.Sprintf("%d.%d.%d.0/24", poolIP[0], poolIP[1], i)
		candidateGateway := fmt.Sprintf("%d.%d.%d.1", poolIP[0], poolIP[1], i)

		if !usedSubnets[candidateSubnet] && !routeProbe(candidateGateway) {
			return candidateSubnet, candidateGateway, i, nil
		}
	}

	return "", "", 0, fmt.Errorf("no available subnets in pool %s", pool)
}

// UsedInstanceSubnets returns the set of /24 CIDRs already claimed by existing
// instances, so subnet allocators can skip them. Instance configs that cannot be
// loaded are logged and skipped (allocation continues around them); instances
// with no recorded subnet are omitted. A failure to enumerate instances is
// returned so callers can decide whether to fail or fall back.
//
// It is shared by every subnet allocator (the default 10.10/16 pool here and the
// vfkit host-mode 192.168.128/24 pool) so the "scan existing instances" logic is
// written once; each allocator keeps its own octet range and exhaustion policy.
func UsedInstanceSubnets() (map[string]bool, error) {
	names, err := List()
	if err != nil {
		return nil, err
	}
	used := make(map[string]bool)
	for _, name := range names {
		inst, _, err := Load(name)
		if err != nil {
			logging.Warn("skipping unreadable instance config during subnet allocation", "instance", name, "error", err)
			continue
		}
		if inst.Subnet != "" {
			used[inst.Subnet] = true
		}
	}
	return used, nil
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
