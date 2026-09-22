//go:build !darwin && !linux

package netroute

// SubnetRouted is a no-op on platforms without a supported route prober: it
// always reports "not routed" so subnet allocation proceeds unchanged.
func SubnetRouted(_ string) bool { return false }
