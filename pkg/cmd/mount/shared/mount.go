package shared

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/mountutil"
	"github.com/sandialabs/abox/internal/procutil"
	"github.com/sandialabs/abox/internal/sshutil"
)

// Mount establishes the SSHFS mount described by entry (local mount point,
// remote path, and the recorded ro/allow_other flags) against user@ip. It
// launches sshfs detached and waits up to 10 seconds for the mount to appear.
// The mount point must already exist; recording the mount is the caller's
// responsibility.
func Mount(paths *config.Paths, user, ip string, entry MountEntry) error {
	return runSSHFS(paths.LogsDir, entry.LocalPath, buildSSHFSArgs(paths, user, ip, entry))
}

// buildSSHFSArgs builds the sshfs argument list.
// Uses the TOFU model matching sshutil.CommonOptions.
func buildSSHFSArgs(paths *config.Paths, sshUser, ip string, entry MountEntry) []string {
	args := []string{
		sshutil.RemotePath(sshUser, ip, entry.RemotePath),
		entry.LocalPath,
		"-o", "IdentityFile=" + paths.SSHKey,
		"-o", "IdentitiesOnly=yes",
		// PubkeyAcceptedKeyTypes is not on sshfs's ssh-option allowlist, so it
		// must go through ssh_command rather than a bare -o (which sshfs would
		// pass to FUSE as an unknown mount option).
		"-o", sshutil.SSHFSCommandOption(),
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile=" + paths.KnownHosts,
		"-o", "LogLevel=ERROR",
	}

	if entry.ReadOnly {
		args = append(args, "-o", "ro")
	}
	if entry.AllowOther {
		args = append(args, "-o", "allow_other")
	}
	return args
}

// runSSHFS launches sshfs detached, sending its output to logsDir/mount.log, and
// waits for the mount at localPath to appear. It returns nil once mounted, or an
// error if sshfs fails or the mount never materializes within the timeout.
//
// sshfs must run detached rather than via a blocking Run(): on macOS macFUSE's
// sshfs stays in the FOREGROUND for the life of the mount, so Run() would never
// return; on Linux sshfs self-daemonizes. Wiring its output to the caller's stdio
// would also let a foreground sshfs hold the caller's pipes open, hanging anything
// reading them (this is what deadlocked the e2e harness). mountutil.IsMounted is
// therefore the source of truth: on Linux the foreground helper exits ~immediately
// after forking the real daemon, so an early clean exit is NOT a failure — only a
// non-zero exit or the mount never appearing is.
func runSSHFS(logsDir, localPath string, sshfsArgs []string) error {
	if err := os.MkdirAll(logsDir, 0o700); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}
	logPath := filepath.Join(logsDir, "mount.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open mount log: %w", err)
	}
	defer logFile.Close()

	cmd := exec.Command("sshfs", sshfsArgs...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	procutil.Detach(cmd) // own process group so the daemon outlives this command

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start sshfs: %w", err)
	}

	// Reap the child so a foreground sshfs that exits early doesn't linger as a
	// zombie, and so we can distinguish an sshfs error from a clean daemonize.
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	const (
		mountTimeout  = 10 * time.Second
		mountInterval = 100 * time.Millisecond
	)
	deadline := time.Now().Add(mountTimeout)
	var exitErr error
	sshfsExited := false
	for !mountutil.IsMounted(localPath) {
		if sshfsExited && exitErr != nil {
			// sshfs is gone with an error and nothing is mounted -> real failure.
			return fmt.Errorf("sshfs failed to mount (see %s): %w", logPath, exitErr)
		}
		if time.Now().After(deadline) {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			return fmt.Errorf("sshfs did not mount %s within %s; see %s", localPath, mountTimeout, logPath)
		}
		select {
		case werr := <-exited:
			exitErr = werr
			sshfsExited = true
		case <-time.After(mountInterval):
		}
	}
	return nil
}
