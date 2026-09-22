package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/netroute"
	"github.com/sandialabs/abox/internal/profiling"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/root"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

func main() {
	os.Exit(run())
}

func run() int {
	// Wire the host-route prober so subnet allocation skips /24s the host already
	// routes elsewhere (e.g. a VPN). Done here (binary only) so unit tests, which
	// never import main, keep the no-op default and don't shell out to ip/route.
	config.SetRouteProbe(netroute.SubnetRouted)

	f := factory.New()
	defer f.Close()
	defer logging.CloseLogFile()

	// Opt-in, env-gated profiling (ABOX_CPUPROFILE / ABOX_TRACE); no-op otherwise.
	// Deferred so it also captures runs that end in an error.
	stopProfiling := profiling.Start()
	defer stopProfiling()

	rootCmd := root.NewCmdRoot(f)
	cmd, err := rootCmd.ExecuteC()
	if err != nil {
		return handleError(f, cmd, err)
	}
	return 0
}

func handleError(f *factory.Factory, cmd interface{ UsageString() string }, err error) int {
	var cancel *cmdutil.ErrCancel
	if errors.As(err, &cancel) {
		return 0
	}

	var silent *cmdutil.ErrSilent
	if errors.As(err, &silent) {
		return 1
	}

	var noResults *cmdutil.NoResultsError
	if errors.As(err, &noResults) {
		if noResults.Message != "" {
			fmt.Fprintln(f.IO.ErrOut, noResults.Message)
		}
		return 0
	}

	var flagErr *cmdutil.ErrFlag
	if errors.As(err, &flagErr) {
		fmt.Fprintln(f.IO.ErrOut, err)
		fmt.Fprintln(f.IO.ErrOut)
		fmt.Fprint(f.IO.ErrOut, cmd.UsageString())
		return 1
	}

	fmt.Fprintln(f.IO.ErrOut, err)

	var hint *cmdutil.ErrHint
	if errors.As(err, &hint) {
		fmt.Fprintln(f.IO.ErrOut)
		fmt.Fprintln(f.IO.ErrOut, hint.Hint)
	}

	return 1
}
