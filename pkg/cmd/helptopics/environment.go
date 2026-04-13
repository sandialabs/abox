package helptopics

import "github.com/spf13/cobra"

const environmentHelpText = `Environment Variables Reference

ABOX_LOG_LEVEL
  Set the log level. Valid values: debug, info, warn, error.
  Equivalent to --log-level flag.

  Example:
    ABOX_LOG_LEVEL=debug abox up

ABOX_LOG_FORMAT
  Set the log format. Valid values: text, json.
  Equivalent to --log-format flag. Default: text.

  Example:
    ABOX_LOG_FORMAT=json abox up

ABOX_LOG_FILE
  Write logs to a file in addition to stderr.
  Equivalent to --log-file flag.

  The file is opened in append mode with 0o600 permissions.
  Parent directories are created if needed.
  Tilde (~) is expanded to the home directory.

  Example:
    ABOX_LOG_FILE=~/.abox.log abox up

ABOX_PRIVILEGE_METHOD
  Privilege escalation method: 'pkexec' or 'sudo'.
  Default: auto-detect (prefers sudo on headless, pkexec with display).

  Use 'sudo' on headless servers without a polkit agent.

  Example:
    ABOX_PRIVILEGE_METHOD=sudo abox up

ABOX_PRIVILEGE_SOCKET
ABOX_PRIVILEGE_TOKEN
  Connect to an external privilege helper instead of spawning one.

  By default, abox spawns a new privilege helper process for each
  CLI invocation that requires elevated privileges. The helper
  exits when the command completes.

  These variables allow connecting to a pre-existing helper, which
  is primarily used for e2e testing to avoid multiple sudo prompts.

  Requirements:
    - Socket path must be in XDG_RUNTIME_DIR or /run/user/<uid>
    - Token must match what the helper expects
    - Helper must be started with matching --allowed-uid

  Example (for e2e tests):
    ABOX_PRIVILEGE_SOCKET=/run/user/1000/abox-test.sock \
    ABOX_PRIVILEGE_TOKEN=<token> abox up

XDG_DATA_HOME
  Base directory for persistent application data.
  Default: ~/.local/share

  Instance data is stored at: $XDG_DATA_HOME/abox/instances/
  Base images are stored at: $XDG_DATA_HOME/abox/base/

  Example:
    XDG_DATA_HOME=/custom/data abox create dev

XDG_RUNTIME_DIR
  Directory for runtime files (sockets, temp files).
  Default: /run/user/<uid>

  Used for:
    - DNS filter Unix sockets
    - Temporary cloud-init ISOs during creation

XDG_CONFIG_HOME
  Base directory for configuration files.
  Default: ~/.config

  Note: abox currently stores all config in XDG_DATA_HOME with instance data.

DEFAULT VALUES
  Data directory:     ~/.local/share/abox/
  Instance directory: ~/.local/share/abox/instances/<name>/
  Base images:        ~/.local/share/abox/base/
  Libvirt images:     /var/lib/libvirt/images/abox/

SEE ALSO
  abox help commands         Command reference
  abox help yaml             abox.yaml configuration reference
  abox help provisioning     Guest-side environment variables
`

// NewCmdEnvironment creates a help topic command for environment variables.
func NewCmdEnvironment() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "environment",
		Short: "Environment variables reference",
		Long:  environmentHelpText,
	}
	// Set Run to show Long text so command appears in its group (not "Additional help topics")
	cmd.Run = func(cmd *cobra.Command, args []string) {
		cmd.Println(cmd.Long)
	}
	return cmd
}
