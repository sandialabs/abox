package images

import "runtime"

// hostArch returns the Go-style architecture name for the current host
// ("amd64", "arm64", etc.). Providers map this to their upstream naming
// convention (Ubuntu/Debian use the same names, AlmaLinux uses "x86_64"/"aarch64").
//
// Declared as a var so tests can stub it if they need to.
var hostArch = func() string {
	return runtime.GOARCH
}
