//go:build darwin

// Package vmnethelper wraps the vmnet-helper CLI
// (https://github.com/nirs/vmnet-helper) for managing per-VM vmnet
// interfaces on macOS. Each helper process owns one vmnet interface
// (= one bridgeN on the host), giving every VM its own isolated
// bridge — the structural analog of libvirt's per-VM bridge on Linux.
package vmnethelper

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// Operation modes accepted by vmnet-helper's --operation-mode flag.
const (
	ModeShared  = "shared"
	ModeHost    = "host"
	ModeBridged = "bridged"
)

// envBinaryPath is the env var used to override the resolved binary path.
const envBinaryPath = "ABOX_VMNET_HELPER_PATH"

// knownBinaryPaths are absolute paths tried (in order) after the env
// override. They match vmnet-helper's Homebrew + install-script docs.
var knownBinaryPaths = []string{
	"/opt/homebrew/opt/vmnet-helper/libexec/vmnet-helper", // Apple Silicon brew
	"/usr/local/opt/vmnet-helper/libexec/vmnet-helper",    // Intel brew
	"/opt/vmnet-helper/bin/vmnet-helper",                  // install.sh script
}

// HelperConfig is the pure input to BuildArgs and Start.
type HelperConfig struct {
	Name            string // instance name (for logging only)
	InterfaceID     string // UUID for MAC stability; reuse instance backend UUID
	OperationMode   string // ModeShared | ModeHost | ModeBridged
	EnableIsolation bool   // adds --enable-isolation
	SocketFD        int    // fd number the child will see the socket at (must be 3 in 11.1)
	UseSudo         bool   // prepend ["sudo", "-n"] to argv
	BinaryPath      string // absolute path; caller populates via ResolveBinaryPath
	PIDFile         string // where to write the process PID
	LogFile         string // where to redirect stderr (optional)
}

// StartResult is the parsed subset of vmnet-helper's one-line JSON
// start message, plus fields we resolve after parsing.
type StartResult struct {
	PID int

	// From vmnet-helper stdout JSON:
	StartAddress string // "vmnet_start_address" — the gateway
	EndAddress   string // "vmnet_end_address"
	SubnetMask   string // "vmnet_subnet_mask"
	MTU          int    // "vmnet_mtu"
	MAC          string // "vmnet_mac_address"
	InterfaceID  string // "vmnet_interface_id"
	NAT66Prefix  string // "vmnet_nat66_prefix" (shared mode only)

	// Resolved after JSON parse via ifconfig scan:
	BridgeInterface string // e.g. "bridge101"
}

// startJSON mirrors the subset of vmnet-helper's stdout JSON we consume.
// Fields not listed here (vmnet_write_max_packets, vmnet_read_max_packets,
// vmnet_max_packet_size) are ignored.
type startJSON struct {
	StartAddress string `json:"vmnet_start_address"`
	EndAddress   string `json:"vmnet_end_address"`
	SubnetMask   string `json:"vmnet_subnet_mask"`
	MTU          int    `json:"vmnet_mtu"`
	MAC          string `json:"vmnet_mac_address"`
	InterfaceID  string `json:"vmnet_interface_id"`
	NAT66Prefix  string `json:"vmnet_nat66_prefix"`
}

// BuildArgs constructs the vmnet-helper CLI argv. Pure — no I/O. When
// cfg.UseSudo is true the slice begins with ["sudo", "-n"] so the
// caller can invoke argv[0] with argv[1:] unchanged. cfg.BinaryPath
// must already be resolved.
//
// Argv shape (sudo prefix omitted when UseSudo=false):
//
//	sudo -n <BinaryPath>
//	  --fd=<SocketFD>
//	  --operation-mode=<OperationMode>
//	  [--enable-isolation]
//	  [--interface-id=<InterfaceID>]
func BuildArgs(cfg HelperConfig) []string {
	var args []string
	if cfg.UseSudo {
		args = append(args, "sudo", "-n")
	}
	args = append(args, cfg.BinaryPath)

	args = append(args, "--fd="+strconv.Itoa(cfg.SocketFD))
	args = append(args, "--operation-mode="+cfg.OperationMode)

	if cfg.EnableIsolation {
		args = append(args, "--enable-isolation")
	}
	if cfg.InterfaceID != "" {
		args = append(args, "--interface-id="+cfg.InterfaceID)
	}

	return args
}

// statFn is injectable for tests.
var statFn = os.Stat

// ResolveBinaryPath returns an absolute path to the vmnet-helper
// binary, checking (in order):
//  1. $ABOX_VMNET_HELPER_PATH
//  2. each entry in knownBinaryPaths
//  3. exec.LookPath("vmnet-helper")
//
// Returns an actionable error if nothing resolves.
func ResolveBinaryPath() (string, error) {
	if override := os.Getenv(envBinaryPath); override != "" {
		if _, err := statFn(override); err != nil {
			return "", fmt.Errorf("%s=%q: %w", envBinaryPath, override, err)
		}
		return override, nil
	}

	for _, p := range knownBinaryPaths {
		if _, err := statFn(p); err == nil {
			return p, nil
		}
	}

	if p, err := exec.LookPath("vmnet-helper"); err == nil {
		return p, nil
	}

	return "", errors.New(
		"vmnet-helper not found — install with " +
			"`brew tap nirs/vmnet-helper && brew install vmnet-helper` or " +
			"`curl -fsSL https://github.com/nirs/vmnet-helper/releases/latest/download/install.sh | bash`, " +
			"or set " + envBinaryPath + " to an absolute path",
	)
}

// productVersionFn is injectable for tests.
var productVersionFn = readProductVersion

// needsSudoOnce + needsSudoVal cache the result of the sw_vers probe.
var (
	needsSudoOnce sync.Once
	needsSudoVal  bool
)

// NeedsSudo reports whether vmnet-helper must be launched via `sudo -n`.
// macOS 15 and earlier require root; macOS 26+ does not. A probe failure
// is treated as "assume we need sudo" so we fail loud at sudo invocation
// rather than silently running as non-root and dying inside the child.
func NeedsSudo() bool {
	needsSudoOnce.Do(func() {
		version, err := productVersionFn()
		if err != nil {
			needsSudoVal = true
			return
		}
		major := macOSMajor(version)
		// major == 0 → unparseable → assume sudo needed.
		needsSudoVal = major < 26
	})
	return needsSudoVal
}

// readProductVersion shells out to `sw_vers -productVersion`.
func readProductVersion() (string, error) {
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return "", fmt.Errorf("run sw_vers: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// macOSMajor parses "15.4" / "26.1.2" / "" into the major version int.
// Returns 0 when unparseable.
func macOSMajor(productVersion string) int {
	s := strings.TrimSpace(productVersion)
	if s == "" {
		return 0
	}
	head, _, _ := strings.Cut(s, ".")
	n, err := strconv.Atoi(head)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// parseStartJSON unmarshals vmnet-helper's one-line stdout start message.
func parseStartJSON(firstLine []byte) (*startJSON, error) {
	trimmed := strings.TrimSpace(string(firstLine))
	if trimmed == "" {
		return nil, errors.New("empty start message from vmnet-helper")
	}
	var sj startJSON
	if err := json.Unmarshal([]byte(trimmed), &sj); err != nil {
		return nil, fmt.Errorf("parse vmnet-helper start JSON: %w", err)
	}
	if sj.StartAddress == "" {
		return nil, errors.New("vmnet-helper start JSON missing vmnet_start_address")
	}
	return &sj, nil
}
