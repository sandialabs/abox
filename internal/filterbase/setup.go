package filterbase

import (
	"fmt"
	"io"

	"github.com/sandialabs/abox/internal/allowlist"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
)

// DaemonSetup holds the common state initialized by SetupDaemon.
type DaemonSetup struct {
	Inst   *config.Instance
	Paths  *config.Paths
	Filter *allowlist.Filter
	Loader *allowlist.Loader
}

// SetupDaemon performs common initialization for filter daemon commands:
// config check, config load, filter creation, allowlist loading, and file watcher start.
// The caller must defer setup.Loader.Stop() after a successful return.
func SetupDaemon(name string, stderr io.Writer) (*DaemonSetup, error) {
	if !config.Exists(name) {
		return nil, fmt.Errorf("instance %q does not exist", name)
	}

	inst, paths, err := config.Load(name)
	if err != nil {
		return nil, err
	}

	filter := allowlist.NewFilter()
	loader := allowlist.NewLoader(paths.Allowlist, filter)

	if err := allowlist.EnsureDir(paths.Allowlist); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := allowlist.CreateDefaultAllowlist(paths.Allowlist); err != nil {
		return nil, fmt.Errorf("failed to create default allowlist: %w", err)
	}

	if err := loader.Load(); err != nil {
		return nil, fmt.Errorf("failed to load allowlist: %w", err)
	}
	fmt.Fprintf(stderr, "Loaded %d domains from %s\n", filter.Count(), paths.Allowlist)

	loader.SetReloadCallback(func(count int, err error) {
		if err != nil {
			logging.Warn("allowlist reload error", "error", err, "instance", name)
		} else {
			fmt.Fprintf(stderr, "Allowlist reloaded: %d domains\n", count)
		}
	})
	if err := loader.Watch(); err != nil {
		logging.Warn("failed to start allowlist watcher", "error", err, "instance", name)
	}

	return &DaemonSetup{
		Inst:   inst,
		Paths:  paths,
		Filter: filter,
		Loader: loader,
	}, nil
}
