//go:build !darwin

package checkdeps

// platformResolveTool provides a hook for platform-specific tool resolution.
// On non-darwin platforms there is nothing to special-case: it always returns
// not-ok so checkOne falls back to the generic PATH-based check, keeping output
// byte-identical to the pre-seam behavior.
func platformResolveTool(_ string) (path string, ok bool, note string) {
	return "", false, ""
}
