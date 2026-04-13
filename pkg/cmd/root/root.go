package root

import (
	"fmt"
	"os"
	"strings"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/validation"
	"github.com/sandialabs/abox/pkg/cmd/allowlist"
	"github.com/sandialabs/abox/pkg/cmd/base"
	"github.com/sandialabs/abox/pkg/cmd/checkdeps"
	"github.com/sandialabs/abox/pkg/cmd/config"
	"github.com/sandialabs/abox/pkg/cmd/create"
	"github.com/sandialabs/abox/pkg/cmd/dns"
	"github.com/sandialabs/abox/pkg/cmd/doctor"
	"github.com/sandialabs/abox/pkg/cmd/down"
	"github.com/sandialabs/abox/pkg/cmd/export"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/forward"
	"github.com/sandialabs/abox/pkg/cmd/helper"
	"github.com/sandialabs/abox/pkg/cmd/helptopics"
	"github.com/sandialabs/abox/pkg/cmd/http"
	importcmd "github.com/sandialabs/abox/pkg/cmd/importcmd"
	initcmd "github.com/sandialabs/abox/pkg/cmd/init"
	"github.com/sandialabs/abox/pkg/cmd/list"
	"github.com/sandialabs/abox/pkg/cmd/logs"
	"github.com/sandialabs/abox/pkg/cmd/monitor"
	"github.com/sandialabs/abox/pkg/cmd/mount"
	"github.com/sandialabs/abox/pkg/cmd/net"
	"github.com/sandialabs/abox/pkg/cmd/overrides"
	"github.com/sandialabs/abox/pkg/cmd/provision"
	"github.com/sandialabs/abox/pkg/cmd/prune"
	"github.com/sandialabs/abox/pkg/cmd/remove"
	"github.com/sandialabs/abox/pkg/cmd/restart"
	"github.com/sandialabs/abox/pkg/cmd/scp"
	"github.com/sandialabs/abox/pkg/cmd/snapshot"
	"github.com/sandialabs/abox/pkg/cmd/ssh"
	"github.com/sandialabs/abox/pkg/cmd/start"
	"github.com/sandialabs/abox/pkg/cmd/status"
	"github.com/sandialabs/abox/pkg/cmd/stop"
	"github.com/sandialabs/abox/pkg/cmd/tap"
	"github.com/sandialabs/abox/pkg/cmd/unmount"
	"github.com/sandialabs/abox/pkg/cmd/up"
	versioncmd "github.com/sandialabs/abox/pkg/cmd/version"

	"github.com/spf13/cobra"

	// Register VM backends via blank imports.
	// Backends self-register in their init() functions.
	_ "github.com/sandialabs/abox/internal/backend/libvirt"
)

// Command group IDs for organizing help output.
const (
	groupDeclarative = "declarative"
	groupLifecycle   = "lifecycle"
	groupSecurity    = "security"
	groupAccess      = "access"
	groupFiles       = "files"
	groupManagement  = "management"
	groupUtilities   = "utilities"
	groupHelp        = "help"

	cmdPrivilegeHelper = "privilege-helper"
)

// NewCmdRoot creates the root command for abox.
func NewCmdRoot(f *factory.Factory) *cobra.Command {
	var logLevel string
	var logFormat string
	var logFile string

	cmd := &cobra.Command{
		Use:   "abox",
		Short: "Manage isolated agent sandbox environments",
		Long: `abox creates and manages security-isolated VM environments for running
AI coding agents with restricted network access.

Each instance gets:
  - Isolated network with DNS allowlist filtering
  - Packet filtering (proxy only, no direct network access)
  - Per-instance configuration and provisioning`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return persistentPreRun(f, cmd, args, logLevel, logFormat, logFile)
		},
	}

	configurePersistentFlags(cmd, &logLevel, &logFormat, &logFile)
	addCommandGroups(cmd)
	addSubcommands(cmd, f)

	return cmd
}

// persistentPreRun handles auto check-deps, root warnings, and logging setup.
func persistentPreRun(f *factory.Factory, cmd *cobra.Command, args []string, logLevel, logFormat, logFile string) error {
	// Auto check-deps on first run / version change
	// Skip for check-deps itself (redundant) and privilege-helper (runs as root)
	if cmd.Name() != "check-deps" && cmd.Name() != cmdPrivilegeHelper {
		if checkdeps.ShouldAutoCheck() {
			if checkdeps.RunQuiet() {
				checkdeps.MarkCheckDone()
			} else {
				fmt.Fprintln(f.IO.ErrOut, "Dependency check failed. Run 'abox check-deps' for details.")
			}
		}
	}

	// Warn if running as root (except for privilege-helper which runs as root by design)
	if os.Geteuid() == 0 && cmd.Name() != cmdPrivilegeHelper {
		logging.Warn("running as root is not recommended")
		fmt.Fprintln(f.IO.ErrOut, "Consider running as a regular user with pkexec/sudo escalation.")
		fmt.Fprintln(f.IO.ErrOut, "")
	}

	if err := initLogging(logLevel, logFormat, logFile); err != nil {
		return err
	}

	// Audit every CLI invocation (skip internal privilege-helper)
	if cmd.Name() != cmdPrivilegeHelper {
		logging.Audit(logging.ActionCLIInvoke,
			"command", cmd.CommandPath(),
			"args", strings.Join(args, " "),
		)
	}
	return nil
}

// initLogging resolves log settings from flags and environment, then initializes logging.
func initLogging(logLevel, logFormat, logFile string) error {
	// Resolve log level: --log-level > ABOX_LOG_LEVEL > default
	levelStr := logLevel
	if levelStr == "" {
		levelStr = os.Getenv("ABOX_LOG_LEVEL")
	}
	if levelStr != "" {
		if err := validation.ValidateLogLevel(levelStr); err != nil {
			return err
		}
	}

	// Resolve log format: --log-format > ABOX_LOG_FORMAT > default
	formatStr := logFormat
	if formatStr == "" {
		formatStr = os.Getenv("ABOX_LOG_FORMAT")
	}
	if formatStr != "" {
		if err := validation.ValidateLogFormat(formatStr); err != nil {
			return err
		}
	}

	// Resolve log file: --log-file > ABOX_LOG_FILE > none
	logFilePath := logFile
	if logFilePath == "" {
		logFilePath = os.Getenv("ABOX_LOG_FILE")
	}

	return logging.InitWithOptions(logging.Options{
		Level:   logging.ParseLevel(levelStr),
		LogFile: logFilePath,
		Format:  formatStr,
	})
}

// configurePersistentFlags adds persistent flags available to all subcommands.
func configurePersistentFlags(cmd *cobra.Command, logLevel, logFormat, logFile *string) {
	cmd.PersistentFlags().StringVar(logLevel, "log-level", "", "Log level (debug, info, warn, error)")
	cmd.PersistentFlags().StringVar(logFormat, "log-format", "", "Log format (text, json)")
	cmd.PersistentFlags().StringVar(logFile, "log-file", "", "Write logs to file (in addition to stderr)")
}

// addCommandGroups defines command groups (order determines help output order).
func addCommandGroups(cmd *cobra.Command) {
	cmd.AddGroup(&cobra.Group{ID: groupDeclarative, Title: "Declarative Workflow:"})
	cmd.AddGroup(&cobra.Group{ID: groupLifecycle, Title: "Instance Lifecycle:"})
	cmd.AddGroup(&cobra.Group{ID: groupSecurity, Title: "Security:"})
	cmd.AddGroup(&cobra.Group{ID: groupAccess, Title: "Access:"})
	cmd.AddGroup(&cobra.Group{ID: groupFiles, Title: "File Transfer:"})
	cmd.AddGroup(&cobra.Group{ID: groupManagement, Title: "Instance Management:"})
	cmd.AddGroup(&cobra.Group{ID: groupUtilities, Title: "Utilities:"})
	cmd.AddGroup(&cobra.Group{ID: groupHelp, Title: "Help Topics:"})

	cmd.SetHelpCommandGroupID(groupHelp)
	cmd.SetCompletionCommandGroupID(groupUtilities)
}

// addGroupedCommand creates a subcommand and adds it with the given group ID.
func addGroupedCommand(cmd *cobra.Command, sub *cobra.Command, group string) {
	sub.GroupID = group
	cmd.AddCommand(sub)
}

// addSubcommands registers all subcommands on the root command.
func addSubcommands(cmd *cobra.Command, f *factory.Factory) {
	// Declarative commands (abox.yaml)
	addGroupedCommand(cmd, initcmd.NewCmdInit(f, nil), groupDeclarative)
	addGroupedCommand(cmd, up.NewCmdUp(f, nil), groupDeclarative)
	addGroupedCommand(cmd, down.NewCmdDown(f, nil), groupDeclarative)

	// Instance lifecycle commands
	addGroupedCommand(cmd, create.NewCmdCreate(f, nil), groupLifecycle)
	addGroupedCommand(cmd, remove.NewCmdRemove(f, nil), groupLifecycle)
	addGroupedCommand(cmd, start.NewCmdStart(f, nil), groupLifecycle)
	addGroupedCommand(cmd, stop.NewCmdStop(f, nil), groupLifecycle)
	addGroupedCommand(cmd, restart.NewCmdRestart(f, nil), groupLifecycle)
	addGroupedCommand(cmd, status.NewCmdStatus(f, nil), groupLifecycle)
	addGroupedCommand(cmd, list.NewCmdList(f, nil), groupLifecycle)

	// Security commands
	addGroupedCommand(cmd, net.NewCmdNet(f), groupSecurity)
	addGroupedCommand(cmd, allowlist.NewCmdAllowlist(f), groupSecurity)
	addGroupedCommand(cmd, dns.NewCmdDNS(f), groupSecurity)
	addGroupedCommand(cmd, http.NewCmdHTTP(f), groupSecurity)
	addGroupedCommand(cmd, monitor.NewCmdMonitor(f), groupSecurity)
	addGroupedCommand(cmd, tap.NewCmdTap(f, nil), groupSecurity)
	addGroupedCommand(cmd, logs.NewCmdLogs(f), groupSecurity)

	// Access commands
	addGroupedCommand(cmd, ssh.NewCmdSSH(f, nil), groupAccess)
	addGroupedCommand(cmd, scp.NewCmdSCP(f, nil), groupAccess)
	addGroupedCommand(cmd, provision.NewCmdProvision(f, nil), groupAccess)
	addGroupedCommand(cmd, forward.NewCmdForward(f), groupAccess)

	// File transfer commands
	addGroupedCommand(cmd, mount.NewCmdMount(f, nil), groupFiles)
	addGroupedCommand(cmd, unmount.NewCmdUnmount(f, nil), groupFiles)
	addGroupedCommand(cmd, export.NewCmdExport(f, nil), groupFiles)
	addGroupedCommand(cmd, importcmd.NewCmdImport(f, nil), groupFiles)

	// Instance management commands
	addGroupedCommand(cmd, config.NewCmdConfig(f), groupManagement)
	addGroupedCommand(cmd, base.NewCmdBase(f), groupManagement)
	addGroupedCommand(cmd, snapshot.NewCmdSnapshot(f), groupManagement)
	addGroupedCommand(cmd, overrides.NewCmdOverrides(f), groupManagement)

	// Help topic commands (need special handling for commandsCmd)
	commandsCmd := helptopics.NewCmdCommands(cmd)
	addGroupedCommand(cmd, commandsCmd, groupHelp)
	addGroupedCommand(cmd, helptopics.NewCmdYaml(), groupHelp)
	addGroupedCommand(cmd, helptopics.NewCmdEnvironment(), groupHelp)
	addGroupedCommand(cmd, helptopics.NewCmdQuickstart(), groupHelp)
	addGroupedCommand(cmd, helptopics.NewCmdFiltering(), groupHelp)
	addGroupedCommand(cmd, helptopics.NewCmdProvisioning(), groupHelp)

	// Utility commands
	addGroupedCommand(cmd, prune.NewCmdPrune(f, nil), groupUtilities)
	addGroupedCommand(cmd, checkdeps.NewCmdCheckDeps(f, nil), groupUtilities)
	addGroupedCommand(cmd, doctor.NewCmdDoctor(f, nil), groupUtilities)
	addGroupedCommand(cmd, versioncmd.NewCmdVersion(f, nil), groupUtilities)

	// Hidden helper command for privilege escalation
	cmd.AddCommand(helper.NewCmdHelper())
}
