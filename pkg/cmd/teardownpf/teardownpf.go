//go:build darwin

// Package teardownpf provides the `abox teardown-pf` command, which removes
// the abox-managed anchor references from /etc/pf.conf on macOS. It's the
// inverse of the auto-wiring done by the privilege helper on first
// `abox start`.
package teardownpf

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sandialabs/abox/internal/firewall"
	"github.com/sandialabs/abox/internal/privilege"
	"github.com/sandialabs/abox/pkg/cmd/factory"
)

// Options holds options for the teardown-pf command.
type Options struct {
	Factory *factory.Factory
}

// NewCmdTeardownPF creates the teardown-pf command.
func NewCmdTeardownPF(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:   "teardown-pf",
		Short: "Remove abox PF anchor references from /etc/pf.conf (macOS)",
		Long: `Remove the abox-managed anchor references from /etc/pf.conf and reload
the main PF ruleset.

abox inserts two anchor reference lines into /etc/pf.conf on first start
(rdr-anchor "abox/*" next to rdr-anchor "com.apple/*", and anchor "abox/*"
next to anchor "com.apple/*") so the kernel evaluates the per-instance pf
rules it loads into abox/<name> sub-anchors. Run this command to undo that
edit; typically as part of 'make uninstall'. Safe to run multiple times.`,
		Example: `  abox teardown-pf
  make uninstall    # calls this for you`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if runF != nil {
				return runF(opts)
			}
			return run(opts)
		},
	}

	return cmd
}

func run(opts *Options) error {
	// pf.conf is mode 0644 by default, so we can read it without privilege.
	// Probe before/after the RPC so we can tell the user whether anything
	// actually changed (the helper silently no-ops when no abox lines are
	// present).
	hadRefs, _ := privilege.HasAnchorReferences(privilege.PfconfDefaultPath)

	client, err := opts.Factory.PrivilegeClient()
	if err != nil {
		return fmt.Errorf("failed to start privilege helper: %w", err)
	}

	pfctl := firewall.NewPfctlClient(client)
	if err := pfctl.TeardownConfig(); err != nil {
		return err
	}

	if hadRefs {
		fmt.Fprintf(opts.Factory.IO.Out,
			"Removed abox anchor references from %s.\n", privilege.PfconfDefaultPath)
	} else {
		fmt.Fprintf(opts.Factory.IO.Out,
			"No abox anchor references found in %s; nothing to do.\n",
			privilege.PfconfDefaultPath)
	}
	return nil
}
