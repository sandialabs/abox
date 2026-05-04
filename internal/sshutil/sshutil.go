// Package sshutil provides helper functions for building SSH commands.
package sshutil

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
)

// CommonOptions returns the standard SSH options used by abox.
// Uses TOFU (Trust On First Use) model with per-instance known_hosts.
//
// Security model:
// - First connection: accept and store the host key (StrictHostKeyChecking=accept-new)
// - Subsequent connections: verify key matches stored key, reject if changed
// - Each instance has its own known_hosts file, cleared on instance destruction
//
// This protects against MITM attacks after first connection while allowing
// ephemeral VMs to work smoothly. If a host key changes unexpectedly, SSH
// will refuse to connect, alerting to a potential attack.
// SSH options shared by all abox SSH/SCP invocations.
const (
	sshOptStrictHostKey = "StrictHostKeyChecking=accept-new"
	sshOptControlPath   = "ControlPath=none"
	sshOptLogLevel      = "LogLevel=ERROR"
)

func CommonOptions(paths *config.Paths) []string {
	return []string{
		"-i", paths.SSHKey,
		"-o", sshOptStrictHostKey,
		"-o", "UserKnownHostsFile=" + paths.KnownHosts,
		"-o", sshOptControlPath,
		"-o", sshOptLogLevel,
	}
}

// Target returns the user@host string for SSH connections.
func Target(user, ip string) string {
	return fmt.Sprintf("%s@%s", user, ip)
}

// BuildSSHArgs builds a complete SSH argument list for connecting to an instance.
// Additional commands can be appended after the target.
func BuildSSHArgs(paths *config.Paths, user, ip string, cmd ...string) []string {
	args := CommonOptions(paths)
	args = append(args, Target(user, ip))
	args = append(args, cmd...)
	return args
}

// BuildSCPArgs builds a complete SCP argument list.
// The source and dest should include the user@host: prefix as needed.
func BuildSCPArgs(paths *config.Paths, source, dest string, recursive bool) []string {
	args := CommonOptions(paths)
	// -O forces legacy SCP protocol instead of SFTP (OpenSSH 9.0+)
	// Required for "/." suffix syntax to work correctly
	prefix := []string{"-O"}
	if recursive {
		prefix = []string{"-r", "-O"}
	}
	args = append(prefix, args...)
	args = append(args, source, dest)
	return args
}

// RemotePath formats a remote path for SCP as user@host:path.
func RemotePath(user, ip, path string) string {
	return fmt.Sprintf("%s@%s:%s", user, ip, path)
}

// TunnelOptions returns SSH options optimized for long-running tunnels.
// These options include keepalive settings to detect and recover from
// connection issues.
func TunnelOptions() []string {
	return []string{
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=3",
	}
}

// WaitForSSH waits for SSH to become available on the target host.
// It tries to connect with a timeout, retrying until maxWait is reached.
// Returns nil when SSH is ready, or an error if the timeout is exceeded.
func WaitForSSH(paths *config.Paths, user, ip string, maxWait time.Duration) error {
	deadline := time.Now().Add(maxWait)
	interval := 2 * time.Second
	attempt := 0

	logging.Debug("waiting for SSH", "host", ip, "user", user, "timeout", maxWait)

	for time.Now().Before(deadline) {
		attempt++
		// Try a simple SSH connection with a short timeout
		args := CommonOptions(paths)
		args = append(args,
			"-o", "ConnectTimeout=5",
			"-o", "BatchMode=yes",
			Target(user, ip),
			"true", // Just run 'true' to test connectivity
		)

		cmd := exec.Command("ssh", args...)
		err := cmd.Run()
		if err == nil {
			logging.Debug("SSH ready", "host", ip, "attempt", attempt)
			return nil // SSH is ready
		}
		logging.Debug("SSH connection attempt failed", "host", ip, "attempt", attempt, "error", err)

		time.Sleep(interval)
	}

	return fmt.Errorf("SSH did not become ready within %v", maxWait)
}
