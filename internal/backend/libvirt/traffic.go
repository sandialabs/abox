//go:build linux

package libvirt

import (
	"context"
	"fmt"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/libvirt"
)

// filterName returns the nwfilter name for an instance.
func filterName(instanceName string) string {
	return "abox-" + instanceName + "-traffic"
}

// TrafficInterceptor implements backend.TrafficInterceptor for libvirt.
// It uses nwfilter rules to control VM network traffic.
type TrafficInterceptor struct{}

// DefineFilter defines a network filter for traffic control.
func (t *TrafficInterceptor) DefineFilter(ctx context.Context, inst *config.Instance) error {
	// Get existing filter UUID if present, so we can update in-place
	existingUUID := libvirt.GetNWFilterUUID(filterName(inst.Name))

	xml, err := libvirt.NWFilterXML(inst, existingUUID)
	if err != nil {
		return fmt.Errorf("failed to generate nwfilter XML: %w", err)
	}

	if err := libvirt.DefineNWFilter(xml); err != nil {
		return fmt.Errorf("failed to define nwfilter: %w", err)
	}

	return nil
}

// ApplyFilter applies a filter to a running VM's network interface.
func (t *TrafficInterceptor) ApplyFilter(ctx context.Context, vmName, networkName, filter, macAddress string, cpus int) error {
	return libvirt.ApplyNWFilter(domainName(vmName), networkName, filter, macAddress, cpus)
}

// RemoveFilter removes a filter from a running VM's network interface.
func (t *TrafficInterceptor) RemoveFilter(ctx context.Context, vmName, networkName, macAddress string, cpus int) error {
	return libvirt.RemoveNWFilter(domainName(vmName), networkName, macAddress, cpus)
}

// DeleteFilter removes a filter definition.
func (t *TrafficInterceptor) DeleteFilter(ctx context.Context, filter string) error {
	return libvirt.DeleteNWFilter(filter)
}

// FilterExists checks if a filter is defined.
func (t *TrafficInterceptor) FilterExists(filter string) bool {
	return libvirt.NWFilterExists(filter)
}

// GetFilterUUID returns the UUID of a filter.
func (t *TrafficInterceptor) GetFilterUUID(filter string) string {
	return libvirt.GetNWFilterUUID(filter)
}
