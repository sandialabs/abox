package status

import (
	"fmt"

	"github.com/sandialabs/abox/internal/dnsfilter"
	"github.com/sandialabs/abox/internal/httpfilter"
	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/list"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// statusJSON is the JSON representation of instance status.
type statusJSON struct {
	Name    string      `json:"name"`
	VM      vmJSON      `json:"vm"`
	Network networkJSON `json:"network"`
	DNS     filterJSON  `json:"dns_filter"`
	HTTP    filterJSON  `json:"http_filter"`
	Domains int32       `json:"allowlist_domains"`
}

type vmJSON struct {
	State  string `json:"state"`
	CPUs   int    `json:"cpus"`
	Memory int    `json:"memory_mb"`
	IP     string `json:"ip,omitempty"`
}

type networkJSON struct {
	Bridge  string `json:"bridge"`
	Subnet  string `json:"subnet"`
	Gateway string `json:"gateway"`
	Active  bool   `json:"active"`
}

type filterJSON struct {
	Running bool   `json:"running"`
	Mode    string `json:"mode,omitempty"`
	Port    int32  `json:"port,omitempty"`
	Total   uint64 `json:"total,omitempty"`
	Allowed uint64 `json:"allowed,omitempty"`
	Blocked uint64 `json:"blocked,omitempty"`
	Uptime  string `json:"uptime,omitempty"`
}

// Options holds the options for the status command.
type Options struct {
	Factory  *factory.Factory
	Exporter *cmdutil.Exporter
	Names    []string // Instance names to show status for
}

// NewCmdStatus creates a new status command.
func NewCmdStatus(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "status [name...]",
		Short: "Show status of one or more abox instances",
		Long: `Show detailed status of one or more abox instances.

Displays VM state, resource configuration, network settings, DNS/HTTP filter
status, and allowlist information. When called without arguments, lists all
instances in table format.`,
		Example: `  abox status dev                          # Show detailed instance status
  abox status                              # List all instances
  abox status dev --json                   # JSON output
  abox status dev --jq '.vm.state'         # Extract a field with jq`,
		Args:              cobra.ArbitraryArgs,
		ValidArgsFunction: completion.Repeat(completion.AllInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Names = args
			if runF != nil {
				return runF(opts)
			}
			if len(args) == 0 {
				// Show all instances
				return list.RunList(f, &cmdutil.Exporter{})
			}

			if opts.Exporter.Enabled() {
				return runStatusJSON(opts, args)
			}

			f.IO.StartPager()
			defer f.IO.StopPager()

			return cmdutil.ForEach(args, func(name string) error {
				return runStatus(opts, name)
			})
		},
	}

	opts.Exporter = cmdutil.AddJSONFlags(cmd)

	return cmd
}

func runStatusJSON(opts *Options, names []string) error {
	var results []statusJSON
	for _, name := range names {
		result, err := collectStatus(opts, name)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		results = append(results, *result)
	}
	if len(results) == 1 {
		return opts.Exporter.Write(opts.Factory.IO.Out, results[0])
	}
	return opts.Exporter.Write(opts.Factory.IO.Out, results)
}

func collectStatus(opts *Options, name string) (*statusJSON, error) {
	inst, _, err := instance.LoadRequired(name)
	if err != nil {
		return nil, err
	}

	factory.Ensure(&opts.Factory)
	be, err := opts.Factory.BackendFor(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get backend: %w", err)
	}

	state := be.VM().State(name)
	result := &statusJSON{
		Name: name,
		VM: vmJSON{
			State:  string(state),
			CPUs:   inst.CPUs,
			Memory: inst.Memory,
		},
		Network: networkJSON{
			Bridge:  inst.Bridge,
			Subnet:  inst.Subnet,
			Gateway: inst.Gateway,
			Active:  be.Network().IsActive(inst.Bridge),
		},
		DNS:  filterJSON{Port: int32(inst.DNS.Port)},  //nolint:gosec // port is 0-65535
		HTTP: filterJSON{Port: int32(inst.HTTP.Port)}, //nolint:gosec // port is 0-65535
	}

	if state == "running" {
		if ip, err := be.VM().GetIP(name); err == nil {
			result.VM.IP = ip
		}
	}

	if client, err := opts.Factory.DNSClient(name); err == nil {
		ctx, cancel := dnsfilter.ClientContext()
		if s, err := client.Status(ctx, &rpc.Empty{}); err == nil {
			result.DNS.Running = true
			result.DNS.Mode = s.Mode
			result.DNS.Total = s.TotalQueries
			result.DNS.Allowed = s.AllowedQueries
			result.DNS.Blocked = s.BlockedQueries
			result.DNS.Uptime = s.Uptime
			result.Domains = s.Domains
		}
		cancel()
	}

	if client, err := opts.Factory.HTTPClient(name); err == nil {
		ctx, cancel := httpfilter.ClientContext()
		if s, err := client.Status(ctx, &rpc.Empty{}); err == nil {
			result.HTTP.Running = true
			result.HTTP.Mode = s.Mode
			result.HTTP.Total = s.TotalRequests
			result.HTTP.Allowed = s.AllowedRequests
			result.HTTP.Blocked = s.BlockedRequests
			result.HTTP.Uptime = s.Uptime
			if result.Domains == 0 {
				result.Domains = s.Domains
			}
		}
		cancel()
	}

	return result, nil
}

func runStatus(opts *Options, name string) error {
	inst, paths, err := instance.LoadRequired(name)
	if err != nil {
		return err
	}

	// Get the backend for this instance
	factory.Ensure(&opts.Factory)
	be, err := opts.Factory.BackendFor(name)
	if err != nil {
		return fmt.Errorf("failed to get backend: %w", err)
	}

	w := opts.Factory.IO.Out
	state := be.VM().State(name)

	fmt.Fprintf(w, "=== Instance: %s ===\n\n", name)

	// VM Status
	fmt.Fprintln(w, "[VM]")
	fmt.Fprintf(w, "  State:    %s\n", state)
	fmt.Fprintf(w, "  CPUs:     %d\n", inst.CPUs)
	fmt.Fprintf(w, "  Memory:   %d MB\n", inst.Memory)

	if state == "running" {
		if ip, err := be.VM().GetIP(name); err == nil {
			fmt.Fprintf(w, "  IP:       %s\n", ip)
		}
	}

	// Network Status
	fmt.Fprintln(w, "\n[Network]")
	fmt.Fprintf(w, "  Bridge:   %s\n", inst.Bridge)
	fmt.Fprintf(w, "  Subnet:   %s\n", inst.Subnet)
	fmt.Fprintf(w, "  Gateway:  %s\n", inst.Gateway)

	networkStatus := "inactive"
	if be.Network().IsActive(inst.Bridge) {
		networkStatus = "active"
	}
	fmt.Fprintf(w, "  Status:   %s\n", networkStatus)

	// Fetch filter statuses once for reuse
	var dnsStatus *rpc.DNSStatus
	var httpStatus *rpc.HTTPStatus

	if client, err := opts.Factory.DNSClient(name); err == nil {
		ctx, cancel := dnsfilter.ClientContext()
		dnsStatus, _ = client.Status(ctx, &rpc.Empty{})
		cancel()
	}

	if client, err := opts.Factory.HTTPClient(name); err == nil {
		ctx, cancel := httpfilter.ClientContext()
		httpStatus, _ = client.Status(ctx, &rpc.Empty{})
		cancel()
	}

	// DNS Filter Status
	fmt.Fprintln(w, "\n[DNS Filter]")
	fmt.Fprintf(w, "  Port:     %d\n", inst.DNS.Port)
	fmt.Fprintf(w, "  Upstream: %s\n", inst.DNS.Upstream)

	if dnsStatus != nil {
		fmt.Fprintf(w, "  Status:   running (%s mode)\n", dnsStatus.Mode)
		fmt.Fprintf(w, "  Queries:  %d total, %d blocked\n", dnsStatus.TotalQueries, dnsStatus.BlockedQueries)
	} else {
		fmt.Fprintf(w, "  Status:   not running\n")
	}

	// HTTP Filter Status
	fmt.Fprintln(w, "\n[HTTP Filter]")
	fmt.Fprintf(w, "  Port:     %d\n", inst.HTTP.Port)

	if httpStatus != nil {
		fmt.Fprintf(w, "  Status:   running (%s mode)\n", httpStatus.Mode)
		fmt.Fprintf(w, "  Requests: %d total, %d blocked\n", httpStatus.TotalRequests, httpStatus.BlockedRequests)
	} else {
		fmt.Fprintf(w, "  Status:   not running\n")
	}

	// Allowlist Status
	fmt.Fprintln(w, "\n[Allowlist]")
	fmt.Fprintf(w, "  File:     %s\n", paths.Allowlist)

	if dnsStatus != nil {
		fmt.Fprintf(w, "  Domains:  %d\n", dnsStatus.Domains)
	} else if httpStatus != nil {
		fmt.Fprintf(w, "  Domains:  %d\n", httpStatus.Domains)
	}

	// Security Status
	fmt.Fprintln(w, "\n[Security]")

	names := be.ResourceNames(name)
	if ti := be.TrafficInterceptor(); ti != nil && ti.FilterExists(names.Filter) {
		fmt.Fprintf(w, "  nwfilter: defined (%s)\n", names.Filter)
	} else {
		fmt.Fprintf(w, "  nwfilter: not defined\n")
	}

	// Paths
	fmt.Fprintln(w, "\n[Paths]")
	fmt.Fprintf(w, "  Config:      %s\n", paths.Config)
	fmt.Fprintf(w, "  Disk:        %s\n", paths.Disk)
	fmt.Fprintf(w, "  SSH Key:     %s\n", paths.SSHKey)
	fmt.Fprintf(w, "  DNS Socket:  %s\n", paths.DNSSocket)
	fmt.Fprintf(w, "  HTTP Socket: %s\n", paths.HTTPSocket)

	return nil
}
