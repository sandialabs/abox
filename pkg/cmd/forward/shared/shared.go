package shared

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/procutil"
	"github.com/sandialabs/abox/internal/sshutil"
)

// ForwardEntry represents a single port forward record.
type ForwardEntry struct {
	HostPort  int       `json:"host_port"`
	GuestPort int       `json:"guest_port"`
	PID       int       `json:"pid"`
	CreatedAt time.Time `json:"created_at"`
	Reverse   bool      `json:"reverse,omitempty"`
}

// ForwardsFile represents the forwards.json structure.
type ForwardsFile struct {
	Forwards []ForwardEntry `json:"forwards"`
}

// GetForwardsFilePath returns the path to forwards.json for an instance.
func GetForwardsFilePath(instanceDir string) string {
	return filepath.Join(instanceDir, "forwards.json")
}

// LoadForwards loads the forwards file for an instance.
func LoadForwards(instanceDir string) (*ForwardsFile, error) {
	path := GetForwardsFilePath(instanceDir)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &ForwardsFile{Forwards: []ForwardEntry{}}, nil
	}
	if err != nil {
		return nil, err
	}

	var forwards ForwardsFile
	if err := json.Unmarshal(data, &forwards); err != nil {
		return nil, err
	}
	return &forwards, nil
}

// SaveForwards saves the forwards file for an instance.
func SaveForwards(instanceDir string, forwards *ForwardsFile) error {
	path := GetForwardsFilePath(instanceDir)
	data, err := json.MarshalIndent(forwards, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// AddForward adds a forward to the forwards file.
func AddForward(instanceDir string, entry ForwardEntry) error {
	forwards, err := LoadForwards(instanceDir)
	if err != nil {
		return err
	}

	forwards.Forwards = append(forwards.Forwards, entry)
	return SaveForwards(instanceDir, forwards)
}

// RemoveForward removes a forward from the forwards file by host port.
func RemoveForward(instanceDir string, hostPort int) error {
	forwards, err := LoadForwards(instanceDir)
	if err != nil {
		return err
	}

	filtered := make([]ForwardEntry, 0, len(forwards.Forwards))
	for _, f := range forwards.Forwards {
		if f.HostPort != hostPort {
			filtered = append(filtered, f)
		}
	}
	forwards.Forwards = filtered

	return SaveForwards(instanceDir, forwards)
}

// FindForwardByHostPort finds a forward entry by host port.
func FindForwardByHostPort(instanceDir string, hostPort int) (*ForwardEntry, error) {
	forwards, err := LoadForwards(instanceDir)
	if err != nil {
		return nil, err
	}

	for _, f := range forwards.Forwards {
		if f.HostPort == hostPort {
			return &f, nil
		}
	}
	return nil, nil //nolint:nilnil // nil means no matching forward found
}

// FindPIDByPattern returns the PID of a process whose command line contains
// every given pattern. The lookup mechanism is platform-specific (see the
// pid_{linux,darwin,other}.go variants) because there is no portable process
// table: Linux scans /proc, darwin shells out to pgrep.

// matchesAll reports whether cmdline contains every pattern. Requiring multiple
// patterns is what keeps tunnel discovery from adopting an unrelated ssh
// process: the forward spec alone (e.g. "localhost:8080:localhost:80") can
// legitimately appear in another instance's tunnel or a user's own ssh
// invocation, so callers additionally require the instance-specific user@ip
// target.
func matchesAll(cmdline string, patterns []string) bool {
	for _, p := range patterns {
		if !strings.Contains(cmdline, p) {
			return false
		}
	}
	return true
}

// IsPIDRunning checks if a process with the given PID is still running.
func IsPIDRunning(pid int) bool {
	return procutil.IsAlive(pid)
}

// UpdateForwardPID updates the PID for an existing forward entry identified by host port.
func UpdateForwardPID(instanceDir string, hostPort int, newPID int) error {
	forwards, err := LoadForwards(instanceDir)
	if err != nil {
		return err
	}

	for i := range forwards.Forwards {
		if forwards.Forwards[i].HostPort == hostPort {
			forwards.Forwards[i].PID = newPID
			return SaveForwards(instanceDir, forwards)
		}
	}

	return fmt.Errorf("no forward found for host port %d", hostPort)
}

// ForwardArg returns the ssh -L/-R forwarding argument for entry
// (e.g. "localhost:8080:localhost:80"). It is the tunnel's cmdline fingerprint:
// StartTunnel passes it to ssh, and FindLiveTunnelPID matches running processes
// against it, so the two can never drift.
func ForwardArg(entry ForwardEntry) string {
	if entry.Reverse {
		return fmt.Sprintf("localhost:%d:localhost:%d", entry.GuestPort, entry.HostPort)
	}
	return fmt.Sprintf("localhost:%d:localhost:%d", entry.HostPort, entry.GuestPort)
}

// FindLiveTunnelPID reports the PID of a live SSH tunnel process for entry by
// matching BOTH its forward argument and the instance's user@ip ssh target
// (the exact string StartTunnel puts on the ssh command line) in the process
// table. Unlike checking IsPIDRunning on the recorded PID, a cmdline match is
// immune to PID reuse: a recycled PID belonging to an unrelated process is not
// mistaken for the tunnel. And unlike matching the forward spec alone, the
// target requirement prevents adopting an unrelated ssh (another instance's
// mirrored forward, or the user's own tunnel elsewhere) — whose PID, once
// recorded, `abox forward remove` would later kill.
func FindLiveTunnelPID(user, ip string, entry ForwardEntry) (int, bool) {
	pid, err := FindPIDByPattern(ForwardArg(entry), sshutil.Target(user, ip))
	if err != nil {
		return 0, false
	}
	return pid, true
}

// StartTunnel spawns an SSH tunnel for the given forward entry and returns the PID.
func StartTunnel(paths *config.Paths, user, ip string, entry ForwardEntry) (int, error) {
	sshArgs := sshutil.CommonOptions(paths)
	// Bound the connection phase so a stalled auth can't hang StartTunnel before
	// ssh -f forks (which happens only after authentication).
	sshArgs = append(sshArgs, sshutil.ConnectTimeoutOptions()...)
	sshArgs = append(sshArgs, sshutil.TunnelOptions()...)

	forwardArg := ForwardArg(entry)
	if entry.Reverse {
		sshArgs = append(sshArgs, "-R", forwardArg)
	} else {
		sshArgs = append(sshArgs, "-L", forwardArg)
	}

	target := sshutil.Target(user, ip)
	sshArgs = append(sshArgs, "-N", "-f", target)

	cmd := exec.Command("ssh", sshArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("failed to create SSH tunnel: %w", err)
	}

	// Match on both the forward spec and the target so a concurrent identical
	// forward against another instance cannot be picked up by mistake.
	pid, err := WaitForSSHProcess(10*time.Second, forwardArg, target)
	if err != nil {
		return 0, fmt.Errorf("SSH tunnel failed to start: %w", err)
	}

	return pid, nil
}

// WaitForSSHProcess waits for an SSH tunnel process matching every pattern to
// start and returns its PID.
func WaitForSSHProcess(timeout time.Duration, patterns ...string) (int, error) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		pid, err := FindPIDByPattern(patterns...)
		if err == nil {
			return pid, nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return 0, errors.New("timeout waiting for SSH process")
}

// CleanupForwards kills all active forwards and clears the forwards file.
func CleanupForwards(instanceDir string) error {
	forwards, err := LoadForwards(instanceDir)
	if err != nil {
		return nil //nolint:nilerr // file doesn't exist or is corrupt; nothing to clean up
	}

	for _, f := range forwards.Forwards {
		if IsPIDRunning(f.PID) {
			_ = procutil.TerminatePID(f.PID)
		}
	}

	// Clear the forwards file
	return SaveForwards(instanceDir, &ForwardsFile{Forwards: []ForwardEntry{}})
}
