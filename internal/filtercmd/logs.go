package filtercmd

import (
	"fmt"
	"io"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logutil"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

// LogOptions holds the options for log viewing.
type LogOptions struct {
	Out     io.Writer // Output writer
	Follow  bool
	Lines   int
	Service bool   // Show service logs instead of traffic logs
	JQ      string // jq expression to filter JSON output
}

// FilterType identifies which filter's logs to view.
type FilterType string

const (
	// FilterDNS represents the DNS filter.
	FilterDNS FilterType = "DNS"
	// FilterHTTP represents the HTTP filter.
	FilterHTTP FilterType = "HTTP"
	// FilterMonitor represents the monitor daemon.
	FilterMonitor FilterType = "Monitor"
)

// logTarget holds the resolved paths and labels for a filter's log files.
type logTarget struct {
	logPath   string
	label     string
	noFileMsg string
}

func resolveLogTarget(paths *config.Paths, filterType FilterType, service bool) (logTarget, error) {
	type targetPair struct {
		traffic logTarget
		svc     logTarget
	}
	targets := map[FilterType]targetPair{
		FilterDNS: {
			traffic: logTarget{paths.DNSTrafficLog, "DNS traffic", "No DNS traffic log found (DNS filter may not have run yet)"},
			svc:     logTarget{paths.DNSServiceLog, "DNS service", "No DNS service log found (DNS filter may not have run yet)"},
		},
		FilterHTTP: {
			traffic: logTarget{paths.HTTPTrafficLog, "HTTP traffic", "No HTTP traffic log found (HTTP filter may not have run yet)"},
			svc:     logTarget{paths.HTTPServiceLog, "HTTP service", "No HTTP service log found (HTTP filter may not have run yet)"},
		},
		FilterMonitor: {
			traffic: logTarget{paths.MonitorLog, "Monitor events", "No monitor log found (monitor daemon may not have run yet)"},
			svc:     logTarget{paths.MonitorServiceLog, "Monitor service", "No monitor service log found (monitor daemon may not have run yet)"},
		},
	}
	pair, ok := targets[filterType]
	if !ok {
		return logTarget{}, fmt.Errorf("unknown filter type: %s", filterType)
	}
	if service {
		return pair.svc, nil
	}
	return pair.traffic, nil
}

// ViewLogs displays logs for the specified filter.
func ViewLogs(opts LogOptions, name string, filterType FilterType) error {
	if !config.Exists(name) {
		return fmt.Errorf("instance %q does not exist", name)
	}

	paths, err := config.GetPaths(name)
	if err != nil {
		return err
	}

	t, err := resolveLogTarget(paths, filterType, opts.Service)
	if err != nil {
		return err
	}

	if opts.JQ != "" {
		return viewWithJQ(opts, t)
	}

	if opts.Follow {
		return logutil.TailFollow(opts.Out, t.logPath, t.label, t.noFileMsg)
	}
	return logutil.TailLines(opts.Out, t.logPath, opts.Lines, t.noFileMsg)
}

func viewWithJQ(opts LogOptions, t logTarget) error {
	if opts.Service {
		return cmdutil.FlagErrorf("--jq cannot be used with --service (service logs are not JSON)")
	}

	if opts.Follow {
		// Follow mode: stream through JQWriter to stdout.
		jqw, err := cmdutil.NewJQWriter(opts.Out, opts.JQ)
		if err != nil {
			return err
		}
		if err := logutil.TailFollow(jqw, t.logPath, t.label, t.noFileMsg); err != nil {
			return err
		}
		return jqw.Flush()
	}

	// Non-follow mode: read entire file through JQ filter,
	// then tail the last N *matching* lines.
	tailBuf := logutil.NewTailBuffer(opts.Out, opts.Lines)
	jqw, err := cmdutil.NewJQWriter(tailBuf, opts.JQ)
	if err != nil {
		return err
	}
	if err := logutil.ReadAll(jqw, t.logPath, t.noFileMsg); err != nil {
		return err
	}
	if err := jqw.Flush(); err != nil {
		return err
	}
	return tailBuf.Flush()
}
