//go:build windows

package vmrun

import (
	"context"
	"errors"
	"fmt"
)

// windowsProvisioner creates and tears down a host-only vmnet via the vnetlib CLI.
// The pure argument builder (windowsHostOnlyCmds) lives in netcfg.go so it stays
// unit-tested on Linux; this file holds only the parts that actually shell out.
type windowsProvisioner struct{}

// activeProvisioner returns the Windows host-only provisioner (vnetlib CLI).
func activeProvisioner() (hostOnlyProvisioner, error) {
	return windowsProvisioner{}, nil
}

// vnetlibTool is the base name of the VMware host-only network CLI on Windows.
const vnetlibTool = "vnetlib"

// hostOnlyToolCandidates returns the Windows host-only network tool names to try,
// in order. Single source of truth for the provisioner and the checkdeps preflight
// (ResolveHostOnlyTool).
func hostOnlyToolCandidates() []string {
	return []string{vnetlibTool, "vnetlib.exe", "vnetlib3", "vnetlib3.exe"}
}

func (windowsProvisioner) configure(ctx context.Context, cfg HostOnlyConfig) error {
	if err := assertNoUplinkConfig(cfg); err != nil {
		return err
	}
	bin, err := resolveNetTool(hostOnlyToolCandidates()...)
	if err != nil {
		return err
	}
	for _, args := range windowsHostOnlyCmds(cfg) {
		if err := runNetCmd(ctx, bin, args...); err != nil {
			return fmt.Errorf("vnetlib %v failed: %w", args, err)
		}
	}
	return nil
}

func (windowsProvisioner) unconfigure(ctx context.Context, vnet string) error {
	if err := assertNoUplink([]string{vnet}); err != nil {
		return err
	}
	bin, err := resolveNetTool(hostOnlyToolCandidates()...)
	if err != nil {
		return err
	}
	// A guard rejection (assertNoUplink) must propagate; a genuine command failure
	// is best-effort "already removed" (adapter absent).
	if err := runNetCmd(ctx, bin, "--", "remove", vnetlibObjAdapter, vnet); err != nil {
		if errors.Is(err, errUplinkForbidden) {
			return err
		}
	}
	return nil
}
