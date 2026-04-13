// Package version provides build version information.
package version

var (
	// Version is the semantic version (injected at build time via ldflags)
	Version = "dev"
	// Commit is the git commit SHA (injected at build time via ldflags)
	Commit = "none"
	// Date is the build date (injected at build time via ldflags)
	Date = "unknown"
)
