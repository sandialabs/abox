package helptopics

import "github.com/spf13/cobra"

const filteringHelpText = `Network Filtering Reference

OVERVIEW
  Each instance runs DNS and HTTP proxy filters sharing a single allowlist.
  DNS filtering intercepts queries (port 53) and returns NXDOMAIN for blocked
  domains. HTTP proxy filtering validates Host headers and blocks SSRF attempts
  to private IPs. Both support active (blocking) and passive (monitoring) modes.

MODES
  abox net filter <name> active     Block domains not in the allowlist (default)
  abox net filter <name> passive    Allow all traffic, capture queried domains

ALLOWLIST
  Both filters share a single allowlist file per instance:
    ~/.local/share/abox/instances/<name>/allowlist.conf

  Syntax:
    *.github.com      Allows github.com and all subdomains
    npmjs.org          Equivalent — subdomains are always included
  Note: sibling domains are NOT matched (e.g. githubusercontent.com needs its own entry).

  Commands:
    abox allowlist add <name> <domain>       Add a domain
    abox allowlist remove <name> <domain>    Remove a domain
    abox allowlist list <name>               List all entries
    abox allowlist edit <name>               Edit in $VISUAL/$EDITOR
    abox allowlist reload <name>             Hot-reload both filters

PROFILING WORKFLOW
  Use profiling to discover which domains a workload needs:

    1. abox net filter dev passive            Switch to passive mode
    2. (run your workload inside the VM)
    3. abox net profile dev show              Review captured domains
    4. abox net profile dev export >> \        Export to allowlist
         ~/.local/share/abox/instances/dev/allowlist.conf
    5. abox allowlist reload dev              Reload both filters
    6. abox net filter dev active             Switch back to active mode

  Other profile commands:
    abox net profile <name> count    Count captured domains
    abox net profile <name> clear    Clear captured domains

STATUS & LOGS
  abox dns status <name>             DNS filter status and stats
  abox http status <name>            HTTP proxy status and stats
  abox dns logs <name>               Stream DNS filter logs
  abox http logs <name>              Stream HTTP proxy logs
  abox dns logs <name> --service     Service logs (systemd/process)
  abox http logs <name> --service    Service logs (systemd/process)

LOG LEVELS
  Adjust runtime log verbosity for filter daemons:

    abox dns level <name>              Show current level
    abox dns level <name> debug        Set DNS filter to debug
    abox http level <name> warn        Set HTTP filter to warn

  Valid levels: debug, info, warn, error

SEE ALSO
  abox help yaml             abox.yaml configuration reference
  abox help provisioning     Provisioning scripts reference
`

// NewCmdFiltering creates a help topic command for network filtering.
func NewCmdFiltering() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "filtering",
		Short: "Network filtering reference",
		Long:  filteringHelpText,
	}
	// Set Run to show Long text so command appears in its group (not "Additional help topics")
	cmd.Run = func(cmd *cobra.Command, args []string) {
		cmd.Println(cmd.Long)
	}
	return cmd
}
