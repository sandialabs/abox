// Package add implements the "abox remote add" command, which registers a git
// remote that routes through "abox ssh".
package add

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/sshutil"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// Options holds the options for the remote add command.
type Options struct {
	Factory    *factory.Factory
	RemoteName string // optional; defaults to the instance name
	Target     string // <instance>:<path>
}

// NewCmdAdd creates a new "remote add" command.
func NewCmdAdd(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:   "add [<remote-name>] <instance>:<path>",
		Short: "Add a git remote that connects to an instance",
		Long: `Add a git remote, in the current repository, that fetches from and pushes to a
git repository inside an abox instance.

The remote routes through 'abox ssh', so it always uses the instance's scoped
SSH key, its per-instance known_hosts, and the instance's current IP address.
Nothing is written to your host SSH configuration, and the remote keeps working
across instance restarts even if the VM's IP address changes.

The path is interpreted on the VM relative to the SSH user's home directory
(the same location 'abox scp <instance>:<path>' writes to), or as an absolute
path if it begins with '/'.

If <remote-name> is omitted, the remote is named after the instance.`,
		Example: `  # In a host clone, add a remote named "dev" for the "dev" box:
  abox remote add dev:projects/my-project

  # Use a custom remote name:
  abox remote add box dev:projects/my-project

  # Then fetch/pull/push as usual:
  git fetch dev
  git pull dev main
  git push dev main`,
		Args:              cobra.RangeArgs(1, 2),
		ValidArgsFunction: completion.Sequence(completion.AllInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 2 {
				opts.RemoteName = args[0]
				opts.Target = args[1]
			} else {
				opts.Target = args[0]
			}
			if runF != nil {
				return runF(opts)
			}
			return opts.Run()
		},
	}

	return cmd
}

// buildExtURL builds the git ext:: transport URL that routes through
// "abox ssh". git's ext:: transport runs the given command and speaks the pack
// protocol over its stdin/stdout; %S is substituted by git with the service
// name (git-upload-pack for fetch, git-receive-pack for push). The instance's
// scoped key, known_hosts, and current IP are all resolved inside "abox ssh".
func buildExtURL(instName, path string) string {
	return fmt.Sprintf("ext::abox ssh %s -- %%S '%s'", instName, path)
}

// Run executes the remote add command.
func (o *Options) Run() error {
	instName, path, isRemote := sshutil.ParseRemotePath(o.Target)
	if !isRemote {
		return fmt.Errorf("target %q must be in <instance>:<path> format", o.Target)
	}
	if path == "" {
		return fmt.Errorf("no path specified in %q; use <instance>:<path>", o.Target)
	}
	// The path is embedded in a single-quoted ext:: argument; an embedded
	// single quote would break git's argument parsing.
	if strings.Contains(path, "'") {
		return fmt.Errorf("path %q must not contain single quotes", path)
	}
	if !config.Exists(instName) {
		return fmt.Errorf("instance %q does not exist", instName)
	}

	remoteName := o.RemoteName
	if remoteName == "" {
		remoteName = instName
	}

	url := buildExtURL(instName, path)

	cmd := exec.Command("git", "remote", "add", remoteName, url)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git remote add: %w (run this inside a git repository)", err)
	}

	logging.AuditInstance(instName, logging.ActionRemoteAdd, "remote", remoteName, "path", path)

	allowSet, err := ensureExtAllowed()
	if err != nil {
		return err
	}

	fmt.Printf("Added git remote %q → instance %q (path %q)\n", remoteName, instName, path)
	if allowSet {
		fmt.Println("Enabled git's ext transport for this repo (protocol.ext.allow=user).")
	}
	fmt.Printf("Try: git fetch %s\n", remoteName)
	return nil
}

// ensureExtAllowed makes sure git will permit the ext:: transport in the
// current repository. git blocks ext:: by default — even for a direct
// "git fetch" — so without this the new remote fails with
// "fatal: transport 'ext' not allowed".
//
// It sets protocol.ext.allow=user at *local* (repo) scope, which permits
// direct user-driven fetch/pull/push while still blocking ext:: inside
// recursive submodule fetches (the case the gate is really protecting against).
// If the effective config already allows ext:: (user or always), it leaves
// config untouched. Returns true if it changed the config.
func ensureExtAllowed() (bool, error) {
	// Effective (merged) value, if any. Errors/unset yield empty output.
	out, _ := exec.Command("git", "config", "--get", "protocol.ext.allow").Output()
	switch strings.TrimSpace(string(out)) {
	case "user", "always":
		return false, nil // already permissive; don't touch the user's config
	}

	cmd := exec.Command("git", "config", "--local", "protocol.ext.allow", "user")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("enable ext transport (protocol.ext.allow): %w", err)
	}
	return true, nil
}
