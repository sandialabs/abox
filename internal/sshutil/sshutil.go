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
	// sshOptIdentitiesOnly pins auth to the identity we pass explicitly (-i, or
	// IdentityFile= for sshfs), so a populated ssh-agent (e.g. macOS Keychain)
	// can't offer other keys first and exhaust the server's MaxAuthTries before
	// ours is tried.
	sshOptIdentitiesOnly = "IdentitiesOnly=yes"
	// sshOptPubkeyAlgos re-enables ed25519 (abox's only key type) for this
	// connection. Hardened clients (corporate/MDM-managed macOS) may exclude
	// ssh-ed25519 from the accepted pubkey algorithms, causing the client to
	// skip our key and fail with "Permission denied (publickey)". The leading
	// '+' appends to the client's built-in default set, and a command-line -o
	// overrides the config-file value, so this affects abox connections only.
	//
	// We use the pre-8.5 keyword PubkeyAcceptedKeyTypes rather than the modern
	// PubkeyAcceptedAlgorithms: OpenSSH 8.5 renamed the option but kept the old
	// name as a permanent alias, so PubkeyAcceptedKeyTypes is understood by
	// every client from 7.0 onward. Passing the 8.5-only name would make older
	// clients (Ubuntu 20.04's 8.2, RHEL 8's 8.0, macOS Big Sur's 8.1) abort
	// with "Bad configuration option" and exit 255 before connecting.
	sshOptPubkeyAlgos = "PubkeyAcceptedKeyTypes=+ssh-ed25519"
	// The following disable client-side forwarding that a compromised guest could
	// exploit to reach back into the operator's session. A guest we connect to is
	// untrusted (that is the whole point of the VM), so:
	//   - ForwardAgent=no: guest root must never be able to use the operator's
	//     ssh-agent to sign with keys it cannot read — that would convert a VM
	//     compromise into operator-credential theft.
	//   - ForwardX11=no / ForwardX11Trusted=no: no X11 channel back to the
	//     operator's display (keystroke injection / screen capture surface).
	// These are set as explicit -o flags so they OVERRIDE any ForwardAgent/
	// ForwardX11 the operator may have enabled globally in ~/.ssh/config (a
	// command-line -o wins over config-file values). abox itself never requests
	// agent/X11 forwarding, so this only ever tightens behavior. We deliberately
	// do NOT set ClearAllForwardings here: the `abox forward` tunnel feature
	// (pkg/cmd/forward) relies on explicit -L/-R port forwards, which that option
	// would cancel. Guest-side sshd config is only defense-in-depth (guest root
	// can re-enable forwarding), so this client-side gate is the load-bearing one.
	sshOptNoAgentFwd   = "ForwardAgent=no"
	sshOptNoX11Fwd     = "ForwardX11=no"
	sshOptNoX11Trusted = "ForwardX11Trusted=no"
)

func CommonOptions(paths *config.Paths) []string {
	return []string{
		"-i", paths.SSHKey,
		"-o", sshOptIdentitiesOnly,
		"-o", sshOptPubkeyAlgos,
		"-o", sshOptStrictHostKey,
		"-o", "UserKnownHostsFile=" + paths.KnownHosts,
		"-o", sshOptControlPath,
		"-o", sshOptLogLevel,
		"-o", sshOptNoAgentFwd,
		"-o", sshOptNoX11Fwd,
		"-o", sshOptNoX11Trusted,
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

// BuildAutomatedSSHArgs is BuildSSHArgs with ConnectTimeoutOptions prepended,
// for non-interactive ssh invocations (provisioning, marker checks, overlay
// transfer) that should never block on connect or prompt for input. Do not use
// it for the interactive `abox ssh` shell — see ConnectTimeoutOptions.
func BuildAutomatedSSHArgs(paths *config.Paths, user, ip string, cmd ...string) []string {
	return append(ConnectTimeoutOptions(), BuildSSHArgs(paths, user, ip, cmd...)...)
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
	// "--" terminates option parsing so a source/dest that begins with "-"
	// (attacker- or instance-influenced path/host) cannot be interpreted as a
	// scp/ssh flag. The "/." suffix syntax the -O legacy mode relies on is
	// unaffected by the separator.
	args = append(args, "--", source, dest)
	return args
}

// RemotePath formats a remote path for SCP as user@host:path.
func RemotePath(user, ip, path string) string {
	return fmt.Sprintf("%s@%s:%s", user, ip, path)
}

// ConnectTimeoutOptions returns SSH options that bound the connection phase
// (ConnectTimeout) and disable interactive prompts (BatchMode). Automated,
// non-interactive ssh/scp invocations should prepend these so a black-holed
// network or an unexpected password prompt can't block indefinitely. abox uses
// passphraseless ed25519 keys, so BatchMode never suppresses a wanted prompt.
//
// Do NOT use these for the interactive `abox ssh` shell — BatchMode there would
// break any legitimate prompt.
func ConnectTimeoutOptions() []string {
	return []string{"-o", "ConnectTimeout=5", "-o", "BatchMode=yes"}
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
		args = append(args, ConnectTimeoutOptions()...)
		args = append(args,
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
