package ssh

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/sshutil"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// Options holds the options for the ssh command.
type Options struct {
	Factory *factory.Factory
	Args    []string // All positional arguments (name + optional command)
}

// NewCmdSSH creates a new ssh command.
func NewCmdSSH(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:   "ssh <name> [-- command...]",
		Short: "SSH into an abox instance",
		Long: `SSH into a running instance.

Opens an interactive shell by default. Pass commands after '--' to execute
them non-interactively. Uses the instance's generated SSH key for authentication.`,
		Example: `  abox ssh dev                    # Interactive shell
  abox ssh dev -- ls -la          # Run a command
  abox ssh dev -- 'echo hello'    # Run with quotes`,
		Args:               cobra.MinimumNArgs(1),
		DisableFlagParsing: true,
		ValidArgsFunction:  completion.Sequence(completion.RunningInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Args = args
			if runF != nil {
				return runF(opts)
			}
			return runSSH(opts.Factory, args)
		},
	}

	return cmd
}

func runSSH(f *factory.Factory, args []string) error {
	name := args[0]

	be, err := f.BackendFor(name)
	if err != nil {
		return fmt.Errorf("failed to get backend: %w", err)
	}

	inst, paths, err := instance.LoadRunning(name, be.VM())
	if err != nil {
		return err
	}

	ip, err := instance.GetIP(inst, be.VM())
	if err != nil {
		return err
	}

	// Build SSH command
	// Note: SSH user is validated at config load time
	sshArgs := sshutil.BuildSSHArgs(paths, inst.GetUser(), ip)

	// Add any additional arguments after --
	if len(args) > 1 {
		// Check for -- separator
		cmdArgs := args[1:]
		if cmdArgs[0] == "--" {
			cmdArgs = cmdArgs[1:]
		}
		sshArgs = append(sshArgs, cmdArgs...)
	}

	// Find ssh binary
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh not found: %w", err)
	}

	// Log SSH access before exec replaces this process
	logging.AuditInstance(name, logging.ActionSSH, "ip", ip)

	// Replace current process with ssh
	return syscall.Exec(sshBin, append([]string{"ssh"}, sshArgs...), os.Environ())
}
