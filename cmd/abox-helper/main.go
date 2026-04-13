// abox-helper is a minimal setuid root binary for the abox privilege helper.
//
// It is designed to be installed as:
//
//	/usr/local/bin/abox-helper
//	owner: root, group: abox, mode: 4750 (setuid, owner=rwx, group=rx)
//
// Members of the "abox" group can run this binary without sudo/pkexec prompts.
// The binary performs strict environment sanitization, FD cleanup, and group
// membership verification before starting the gRPC privilege helper server.
//
// Security properties:
//   - Environment cleared; PATH and LC_ALL set to known-safe values
//   - All inherited file descriptors > 2 are closed
//   - FDs 0/1/2 guaranteed open (prevents fd-reuse attacks)
//   - Core dumps disabled (defense-in-depth; kernel already does this for setuid)
//   - Caller must be in the "abox" group
//   - euid must be 0 (setuid) and real uid must not be 0 (not direct root)
//   - Go static linking eliminates LD_PRELOAD/LD_LIBRARY_PATH attacks
package main

import (
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/user"
	"slices"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/privilege"
	"github.com/sandialabs/abox/internal/version"
)

const (
	// aboxGroup is the Unix group required for setuid helper access.
	aboxGroup = "abox"
)

func main() {
	// Step 1: Clear environment and set safe defaults.
	// This prevents PATH manipulation, LD_* attacks (though Go is static),
	// and other environment-based exploits.
	os.Clearenv()
	_ = os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
	_ = os.Setenv("LC_ALL", "C")

	// Step 2: Close all inherited file descriptors > 2.
	// Prevents leaking sensitive FDs from the parent process.
	closeInheritedFDs()

	// Step 3: Ensure FDs 0/1/2 are open.
	// If any are closed, open /dev/null to prevent fd-reuse attacks where
	// a newly opened file (e.g., the socket) gets fd 0/1/2 and is then
	// inadvertently read/written by library code.
	ensureStdFDs()

	// Step 4: Disable core dumps (defense-in-depth).
	// The kernel already disables dumpable for setuid processes, but
	// set RLIMIT_CORE=0 as belt-and-suspenders.
	disableCoreDumps()

	// Handle --version before security checks (informational only).
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-v" {
			fmt.Printf("abox-helper %s (commit: %s, built: %s)\n", version.Version, version.Commit, version.Date)
			return
		}
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "abox-helper: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Step 5: Verify this is a true setuid invocation.
	// euid must be 0 (setuid bit) and real uid must not be 0.
	euid := os.Geteuid()
	ruid := os.Getuid()
	if euid != 0 {
		return fmt.Errorf("must be installed setuid root (euid=%d)", euid)
	}
	if ruid == 0 {
		return errors.New("must not be run directly as root; use setuid invocation")
	}

	// Step 6: Verify caller is in the "abox" group.
	if err := verifyAboxGroup(ruid); err != nil {
		return err
	}

	// Step 7: Parse flags.
	socketPath, err := parseFlags()
	if err != nil {
		return err
	}

	// Step 8: Initialize audit logging (syslog only).
	if err := logging.InitWithOptions(logging.Options{Format: "text"}); err != nil {
		// Non-fatal: continue without syslog
		fmt.Fprintf(os.Stderr, "warning: failed to init logging: %v\n", err)
	}

	logging.Audit("privilege-helper.start",
		"action", "privilege-helper.start",
		"caller_uid", ruid,
		"pid", os.Getpid(),
		"socket", socketPath,
		"mode", "setuid",
	)

	// Step 9: Resolve absolute paths for external commands.
	if err := privilege.ResolveCommands(); err != nil {
		return fmt.Errorf("failed to resolve command paths: %w", err)
	}

	// Step 10: Run the privilege helper (reads token from stdin, starts gRPC).
	// Use the kernel-provided real UID directly — unforgeable in setuid context.
	return privilege.RunHelper(socketPath, ruid)
}

// closeInheritedFDs marks all file descriptors > 2 as close-on-exec.
// Uses CLOSE_RANGE_CLOEXEC on kernels >= 5.11 for an atomic, race-free mark.
// Falls back to setting CLOEXEC individually via /proc/self/fd.
//
// We use CLOEXEC instead of closing because closing destroys Go runtime
// internal FDs (epoll fd for netpoller, signal notification pipe), causing
// EBADF when the runtime later tries to use them. CLOEXEC prevents inherited
// FDs from leaking to child processes (iptables, qemu-img, etc.) without
// affecting the current process.
func closeInheritedFDs() {
	// Try close_range with CLOEXEC first — atomic, no race with directory fd.
	if err := unix.CloseRange(3, uint(math.MaxUint32), unix.CLOSE_RANGE_CLOEXEC); err == nil {
		return
	}

	// Fallback: set CLOEXEC individually via /proc/self/fd.
	// Open the directory manually so we know its exact fd to skip.
	dirFD, err := unix.Open("/proc/self/fd", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return
	}
	defer func() { _ = unix.Close(dirFD) }()

	// Use the directory fd to read entries via /proc/self/fd/<dirFD>
	dirPath := fmt.Sprintf("/proc/self/fd/%d", dirFD)
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil || fd <= 2 || fd == dirFD {
			continue
		}
		unix.CloseOnExec(fd)
	}
}

// ensureStdFDs ensures file descriptors 0, 1, 2 are open.
// If any are closed, open /dev/null to fill the slot, preventing
// fd-reuse attacks where a privileged file gets fd 0/1/2.
func ensureStdFDs() {
	for fd := range 3 {
		// Use fcntl F_GETFD to check if fd is open (cheapest check).
		_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil {
			// FD is closed; open /dev/null to fill the slot.
			// Use the raw syscall to ensure we get the lowest available fd.
			nullFD, openErr := unix.Open("/dev/null", unix.O_RDWR, 0)
			if openErr != nil {
				// If we can't open /dev/null, abort.
				fmt.Fprintf(os.Stderr, "fatal: cannot open /dev/null for fd %d: %v\n", fd, openErr)
				os.Exit(1)
			}
			// If we got a different fd than expected, dup2 it.
			if nullFD != fd {
				_ = unix.Dup2(nullFD, fd)
				_ = unix.Close(nullFD)
			}
		}
	}
}

// disableCoreDumps sets RLIMIT_CORE to 0.
func disableCoreDumps() {
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}

// verifyAboxGroup checks that the real user (by UID) is a member of the "abox" group.
// We look up the user by their real UID, then check their group memberships.
func verifyAboxGroup(ruid int) error {
	u, err := user.LookupId(strconv.Itoa(ruid))
	if err != nil {
		return fmt.Errorf("failed to look up user for uid %d: %w", ruid, err)
	}

	gids, err := u.GroupIds()
	if err != nil {
		return fmt.Errorf("failed to get groups for user %s: %w", u.Username, err)
	}

	aboxGrp, err := user.LookupGroup(aboxGroup)
	if err != nil {
		return fmt.Errorf("group %q does not exist; create it with: sudo groupadd --system %s", aboxGroup, aboxGroup)
	}

	if slices.Contains(gids, aboxGrp.Gid) {
		return nil
	}

	return fmt.Errorf("user %s is not in the %q group; add with: sudo usermod -aG %s %s",
		u.Username, aboxGroup, aboxGroup, u.Username)
}

// parseFlags parses --socket from os.Args using the flag stdlib.
// The setuid binary does not accept --allowed-uid; it uses the kernel-provided
// real UID (os.Getuid()) which is unforgeable.
func parseFlags() (string, error) {
	fs := flag.NewFlagSet("abox-helper", flag.ContinueOnError)
	socketPath := fs.String("socket", "", "Unix socket path")
	_ = fs.Bool("token-stdin", false, "Compatibility flag (token is always read from stdin)")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return "", err
	}

	if err := privilege.ValidateSocketPath(*socketPath); err != nil {
		return "", fmt.Errorf("--socket: %w", err)
	}

	return *socketPath, nil
}
