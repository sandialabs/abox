//go:build darwin

package vfkit

import (
	"fmt"
	"path/filepath"
	"strconv"
)

// NetFDChild is the fd number the vfkit child sees the network
// socketpair end at. cmd.ExtraFiles[0] maps to fd 3 in the child;
// VMConfig.NetFD must match this value.
const NetFDChild = 3

// VMConfig holds the configuration for launching a vfkit VM instance.
type VMConfig struct {
	Name         string // instance name (for logging)
	CPUs         int
	MemoryMB     int
	DiskPath     string // path to raw disk image (vfkit only supports raw format)
	CloudInitISO string // path to cidata.iso (optional, empty to skip)
	MACAddress   string // e.g. "02:ab:00:xx:xx:xx"
	ConsoleLog   string // path for virtio-serial console output (optional)
	RESTfulURI   string // e.g. "tcp://localhost:12345" (optional)
	PIDFile      string // where to write the vfkit process PID
	LogFile      string // where to redirect vfkit stderr (optional)
	NetFD        int    // child-side fd number for the virtio-net socketpair end; must be NetFDChild
}

// EFIStorePath returns the path for the EFI variable store,
// derived from the disk path's parent directory.
func (c VMConfig) EFIStorePath() string {
	return filepath.Join(filepath.Dir(c.DiskPath), "efi-variable-store")
}

// BuildArgs constructs the vfkit CLI arguments from a VMConfig.
// This is a pure function with no I/O, making it fully testable.
func BuildArgs(cfg VMConfig) []string {
	args := []string{
		"--cpus", strconv.Itoa(cfg.CPUs),
		"--memory", strconv.Itoa(cfg.MemoryMB),
	}

	// Boot disk
	args = append(args, "--device", "virtio-blk,path="+cfg.DiskPath)

	// Cloud-init ISO as second block device (NoCloud datasource detects it)
	if cfg.CloudInitISO != "" {
		args = append(args, "--device", "virtio-blk,path="+cfg.CloudInitISO)
	}

	// Network: virtio-net attached to a file descriptor. The caller hands
	// vfkit one end of a socketpair via cmd.ExtraFiles; the other end is
	// connected to a vmnet-helper process that provides NAT/DHCP.
	// cfg.NetFD is rendered verbatim — StartVM enforces it equals NetFDChild.
	args = append(args, "--device",
		fmt.Sprintf("virtio-net,fd=%d,mac=%s", cfg.NetFD, cfg.MACAddress))

	// Console log via virtio-serial
	if cfg.ConsoleLog != "" {
		args = append(args, "--device", "virtio-serial,logFilePath="+cfg.ConsoleLog)
	}

	// EFI bootloader (required for Apple Silicon with standard Linux images)
	args = append(args, "--bootloader",
		"efi,variable-store="+cfg.EFIStorePath()+",create")

	// REST API for lifecycle control
	if cfg.RESTfulURI != "" {
		args = append(args, "--restful-uri", cfg.RESTfulURI)
	}

	return args
}
