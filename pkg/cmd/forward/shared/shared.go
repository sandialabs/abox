package shared

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

// FindPIDByPattern returns the PID of a process whose command line contains the
// given pattern. The lookup mechanism is platform-specific (see the
// pid_{linux,darwin,other}.go variants) because there is no portable process
// table: Linux scans /proc, darwin shells out to pgrep.

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

// StartTunnel spawns an SSH tunnel for the given forward entry and returns the PID.
func StartTunnel(paths *config.Paths, user, ip string, entry ForwardEntry) (int, error) {
	sshArgs := sshutil.CommonOptions(paths)
	// Bound the connection phase so a stalled auth can't hang StartTunnel before
	// ssh -f forks (which happens only after authentication).
	sshArgs = append(sshArgs, sshutil.ConnectTimeoutOptions()...)
	sshArgs = append(sshArgs, sshutil.TunnelOptions()...)

	var forwardArg string
	if entry.Reverse {
		forwardArg = fmt.Sprintf("localhost:%d:localhost:%d", entry.GuestPort, entry.HostPort)
		sshArgs = append(sshArgs, "-R", forwardArg)
	} else {
		forwardArg = fmt.Sprintf("localhost:%d:localhost:%d", entry.HostPort, entry.GuestPort)
		sshArgs = append(sshArgs, "-L", forwardArg)
	}

	sshArgs = append(sshArgs, "-N", "-f", sshutil.Target(user, ip))

	cmd := exec.Command("ssh", sshArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("failed to create SSH tunnel: %w", err)
	}

	pid, err := WaitForSSHProcess(forwardArg, 10*time.Second)
	if err != nil {
		return 0, fmt.Errorf("SSH tunnel failed to start: %w", err)
	}

	return pid, nil
}

// WaitForSSHProcess waits for the SSH tunnel process to start and returns the PID.
func WaitForSSHProcess(pattern string, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		pid, err := FindPIDByPattern(pattern)
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
