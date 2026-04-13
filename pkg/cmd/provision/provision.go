package provision

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/sshutil"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// Options holds the options for the provision command.
type Options struct {
	Factory *factory.Factory
	Scripts []string // Provision scripts to run (CLI flag or abox.yaml)
	Overlay string
	Brief   bool   // Suppress final summary output
	Name    string // Instance name (positional arg)

	OnScriptStart func(index int)            // called before each script runs
	OnScriptDone  func(index int, err error) // called after each script completes
}

// NewCmdProvision creates a new provision command.
func NewCmdProvision(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "provision <name>",
		Short: "Run provision scripts on an instance",
		Long: `Run provision scripts on a running instance.

Provision scripts are shell scripts that run inside the VM to install
packages and configure the environment.`,
		Example: `  abox provision dev                              # Run default provision.sh
  abox provision dev -s setup.sh                  # Run specific script
  abox provision dev -s first.sh -s second.sh    # Run multiple scripts`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completion.Sequence(completion.RunningInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if runF != nil {
				return runF(opts)
			}
			return runProvision(opts, opts.Name)
		},
	}

	cmd.Flags().StringArrayVarP(&opts.Scripts, "script", "s", nil, "Provision script to run (can be specified multiple times)")
	cmd.Flags().StringVar(&opts.Overlay, "overlay", "", "Directory to mount at /tmp/abox/overlay during provisioning")

	return cmd
}

// Run executes the provision command with the given options and instance name.
func Run(_ context.Context, opts *Options, name string) error {
	return runProvision(opts, name)
}

func runProvision(opts *Options, name string) error {
	factory.Ensure(&opts.Factory)
	be, err := opts.Factory.BackendFor(name)
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

	// Determine script paths
	scriptPaths := opts.Scripts
	if len(scriptPaths) == 0 {
		// Check for default provision.sh in instance directory
		defaultScript := filepath.Join(paths.Instance, "provision.sh")
		if _, err := os.Stat(defaultScript); err != nil {
			return &cmdutil.ErrHint{
				Err:  errors.New("no provision script specified and no default provision.sh found"),
				Hint: fmt.Sprintf("Create one at: %s\nOr specify with: abox provision %s -s <script>", defaultScript, name),
			}
		}
		scriptPaths = []string{defaultScript}
	}

	// Note: SSH user is validated at config load time
	sshUser := inst.GetUser()
	w := opts.Factory.IO.Out

	// Mount overlay directory if specified
	if opts.Overlay != "" {
		if err := mountOverlay(w, paths, sshUser, ip, opts.Overlay); err != nil {
			return fmt.Errorf("failed to mount overlay: %w", err)
		}
		defer unmountOverlay(w, paths, sshUser, ip)
	}

	// Run each script
	hasOverlay := opts.Overlay != ""
	for i, scriptPath := range scriptPaths {
		if opts.OnScriptStart != nil {
			opts.OnScriptStart(i)
		}
		if err := runScript(w, paths, inst, ip, hasOverlay, scriptPath); err != nil {
			if opts.OnScriptDone != nil {
				opts.OnScriptDone(i, err)
			}
			return err
		}
		if opts.OnScriptDone != nil {
			opts.OnScriptDone(i, nil)
		}
	}

	if !opts.Brief {
		fmt.Fprintln(w, "Provision completed successfully.")
	}

	logging.AuditInstance(name, logging.ActionProvision, "scripts", len(scriptPaths))

	return nil
}

func runScript(w io.Writer, paths *config.Paths, inst *config.Instance, ip string, hasOverlay bool, scriptPath string) error {
	// Read script content
	script, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to read provision script: %w", err)
	}

	logging.Debug("running provision script", "script", scriptPath, "instance", inst.Name, "ip", ip)
	fmt.Fprintf(w, "Running provision script: %s\n", scriptPath)
	fmt.Fprintln(w, strings.Repeat("-", 60))

	// Build environment preamble and prepend to script.
	// Append a completion marker that is only written if the entire script
	// succeeds (respects set -e). Used to distinguish SSH drops that happen
	// after the script finishes from mid-script failures.
	nonce := strconv.FormatInt(time.Now().UnixNano(), 10)
	marker := "/tmp/.abox-provision-ok-" + nonce

	preamble := buildEnvPreamble(inst, ip, hasOverlay)
	scriptWithEnv := preamble + string(script) + fmt.Sprintf("\ntouch %s\n", marker)

	// Execute script via SSH
	sshUser := inst.GetUser()
	sshArgs := sshutil.BuildSSHArgs(paths, sshUser, ip, "sudo", "bash", "-s")

	sshCmd := exec.Command("ssh", sshArgs...)
	sshCmd.Stdin = strings.NewReader(scriptWithEnv)
	sshCmd.Stdout = w
	sshCmd.Stderr = w // Merged with stdout so both appear in TUI output panel

	if err := sshCmd.Run(); err != nil {
		if !isSSHConnectionError(err) {
			return fmt.Errorf("provision failed: %w", err)
		}
		return handleSSHDrop(w, paths, sshUser, ip, marker)
	}

	cleanupMarker(paths, sshUser, ip, marker)
	fmt.Fprintln(w, strings.Repeat("-", 60))
	return nil
}

func handleSSHDrop(w io.Writer, paths *config.Paths, sshUser, ip, marker string) error {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "SSH connection lost — possibly due to a service restart inside the VM.")
	fmt.Fprintln(w, "Waiting for SSH to come back...")

	if waitErr := sshutil.WaitForSSH(paths, sshUser, ip, 120*time.Second); waitErr != nil {
		return fmt.Errorf("failed to provision: SSH connection lost and VM did not become reachable again: %w", waitErr)
	}

	if checkMarker(paths, sshUser, ip, marker) {
		cleanupMarker(paths, sshUser, ip, marker)
		fmt.Fprintln(w, "Script completed successfully before the SSH connection dropped.")
		fmt.Fprintln(w, strings.Repeat("-", 60))
		return nil
	}

	return errors.New("provision failed: SSH connection lost while script was still running (exit status 255)")
}

// isSSHConnectionError returns true if the error indicates an SSH connection
// failure (exit status 255).
func isSSHConnectionError(err error) bool {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode() == 255
	}
	return false
}

// checkMarker tests whether the completion marker file exists in the VM.
func checkMarker(paths *config.Paths, user, ip, marker string) bool {
	args := sshutil.BuildSSHArgs(paths, user, ip, "test", "-f", marker)
	cmd := exec.Command("ssh", args...)
	return cmd.Run() == nil
}

// cleanupMarker removes the completion marker file from the VM (best-effort).
func cleanupMarker(paths *config.Paths, user, ip, marker string) {
	args := sshutil.BuildSSHArgs(paths, user, ip, "rm", "-f", marker)
	cmd := exec.Command("ssh", args...)
	_ = cmd.Run()
}

// buildEnvPreamble creates export statements for provision script environment.
// All values are pre-validated or inherently safe:
// - Names/Users: Strict regex [a-zA-Z][a-zA-Z0-9_-]* - no spaces or shell metacharacters
// - IPs/Subnets: Only digits, dots, slash
// - Ports: Integers
// - Overlay: Constant string
// Using %q formatting for defense-in-depth.
func buildEnvPreamble(inst *config.Instance, ip string, hasOverlay bool) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "export ABOX_NAME=%q\n", inst.Name)
	fmt.Fprintf(&sb, "export ABOX_USER=%q\n", inst.GetUser())
	fmt.Fprintf(&sb, "export ABOX_IP=%q\n", ip)
	fmt.Fprintf(&sb, "export ABOX_GATEWAY=%q\n", inst.Gateway)
	fmt.Fprintf(&sb, "export ABOX_SUBNET=%q\n", inst.Subnet)
	if hasOverlay {
		fmt.Fprintf(&sb, "export ABOX_OVERLAY=%q\n", overlayMountPoint)
	}

	// Suppress needrestart auto-restarts (prevents SSH drops during apt-get).
	fmt.Fprintf(&sb, "export NEEDRESTART_SUSPEND=%q\n", "1")
	// Prevent dpkg configuration prompts.
	fmt.Fprintf(&sb, "export DEBIAN_FRONTEND=%q\n", "noninteractive")

	// Set proxy environment variables so provision scripts use the HTTP filter.
	// This is required because the nwfilter blocks direct connections.
	if inst.HTTP.Port > 0 {
		proxyURL := "http://" + net.JoinHostPort(inst.Gateway, strconv.Itoa(inst.HTTP.Port))
		noProxy := "localhost,127.0.0.1," + inst.Gateway
		fmt.Fprintf(&sb, "export HTTP_PROXY=%q\n", proxyURL)
		fmt.Fprintf(&sb, "export HTTPS_PROXY=%q\n", proxyURL)
		fmt.Fprintf(&sb, "export http_proxy=%q\n", proxyURL)
		fmt.Fprintf(&sb, "export https_proxy=%q\n", proxyURL)
		fmt.Fprintf(&sb, "export NO_PROXY=%q\n", noProxy)
		fmt.Fprintf(&sb, "export no_proxy=%q\n", noProxy)
	}

	// Ensure /usr/local/bin is in PATH (not in sudo secure_path on RHEL).
	fmt.Fprintln(&sb, `export PATH="$PATH:/usr/local/bin"`)

	sb.WriteString("\n")
	return sb.String()
}

const overlayMountPoint = "/tmp/abox/overlay"

// mountOverlay mounts a host directory to the VM using reverse sshfs.
func mountOverlay(w io.Writer, paths *config.Paths, user, ip, localDir string) error {
	// Expand local path
	if strings.HasPrefix(localDir, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		localDir = filepath.Join(home, localDir[2:])
	}

	absLocalDir, err := filepath.Abs(localDir)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	// Verify overlay directory exists
	if _, err := os.Stat(absLocalDir); os.IsNotExist(err) {
		return fmt.Errorf("overlay directory does not exist: %s", absLocalDir)
	}

	fmt.Fprintf(w, "Mounting overlay: %s -> %s\n", absLocalDir, overlayMountPoint)

	// Create mount point in VM using separate commands to avoid shell injection
	// Note: user is validated via ValidateSSHUser at config load time
	// overlayMountPoint is a constant
	if err := runSSHCommand(w, paths, user, ip, "sudo", "mkdir", "-p", overlayMountPoint); err != nil {
		return fmt.Errorf("failed to create mount point: %w", err)
	}
	if err := runSSHCommand(w, paths, user, ip, "sudo", "chown", user+":"+user, overlayMountPoint); err != nil {
		return fmt.Errorf("failed to set mount point ownership: %w", err)
	}

	// Copy directory contents using tar over ssh.
	// This is more reliable than scp with "/." syntax which fails on some OpenSSH versions.
	// We create a tar stream locally and extract it remotely via ssh.
	tarCmd := exec.Command("tar", "-C", absLocalDir, "-cf", "-", ".")
	sshArgs := sshutil.BuildSSHArgs(paths, user, ip, "tar", "-C", overlayMountPoint, "-xf", "-")
	sshCmd := exec.Command("ssh", sshArgs...)

	// Pipe tar output to ssh input
	pipe, err := tarCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create pipe: %w", err)
	}
	sshCmd.Stdin = pipe
	sshCmd.Stdout = w
	sshCmd.Stderr = w

	if err := tarCmd.Start(); err != nil {
		return fmt.Errorf("failed to start tar: %w", err)
	}
	if err := sshCmd.Start(); err != nil {
		_ = tarCmd.Process.Kill()
		return fmt.Errorf("failed to start ssh: %w", err)
	}

	// Wait for both commands
	tarErr := tarCmd.Wait()
	sshErr := sshCmd.Wait()
	if tarErr != nil {
		return fmt.Errorf("tar failed: %w", tarErr)
	}
	if sshErr != nil {
		return fmt.Errorf("ssh extract failed: %w", sshErr)
	}

	return nil
}

// unmountOverlay cleans up the overlay mount point.
func unmountOverlay(w io.Writer, paths *config.Paths, user, ip string) {
	fmt.Fprintln(w, "Cleaning up overlay...")
	// Remove the overlay directory using separate args to avoid shell injection
	// overlayMountPoint is a constant, so this is safe
	_ = runSSHCommand(w, paths, user, ip, "sudo", "rm", "-rf", overlayMountPoint)
}

// runSSHCommand runs a command on the VM with arguments passed separately.
// This avoids shell injection by not concatenating arguments into a shell string.
// Each argument is passed to ssh separately, which joins them with spaces.
func runSSHCommand(w io.Writer, paths *config.Paths, user, ip string, args ...string) error {
	sshArgs := sshutil.BuildSSHArgs(paths, user, ip, args...)
	cmd := exec.Command("ssh", sshArgs...)
	cmd.Stdout = w
	cmd.Stderr = w
	return cmd.Run()
}
