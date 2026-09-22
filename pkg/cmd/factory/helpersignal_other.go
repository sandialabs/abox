//go:build !darwin

package factory

// ConfigureInteractiveHelperSignaling is a no-op off macOS: only the darwin vfkit
// backend launches a root-owned vmnet-helper that needs an interactive `sudo kill`
// fallback. See the darwin build of this method for details.
func (f *Factory) ConfigureInteractiveHelperSignaling() {}
