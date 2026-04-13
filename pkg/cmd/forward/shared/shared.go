package shared

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sandialabs/abox/internal/config"
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

// FindPIDByPattern scans /proc/*/cmdline for a process matching the given pattern.
func FindPIDByPattern(pattern string) (int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // Not a PID directory
		}

		// No /proc/[pid]/exe check: this function finds SSH tunnel processes
		// (not abox processes), so the exe is /usr/bin/ssh, not our binary.
		// The cmdline pattern (e.g. "localhost:8080:localhost:80") is specific
		// enough to avoid false matches.
		cmdlinePath := filepath.Join("/proc", entry.Name(), "cmdline")
		data, err := os.ReadFile(cmdlinePath)
		if err != nil {
			continue // Process may have exited
		}

		// cmdline uses null bytes as separators
		cmdline := strings.ReplaceAll(string(data), "\x00", " ")
		if strings.Contains(cmdline, pattern) {
			return pid, nil
		}
	}

	return 0, fmt.Errorf("no process found matching pattern: %s", pattern)
}

// IsPIDRunning checks if a process with the given PID is still running.
func IsPIDRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	// Sending signal 0 to a process checks if it exists without actually sending a signal
	err := syscall.Kill(pid, 0)
	return err == nil
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
			_ = syscall.Kill(f.PID, syscall.SIGTERM)
		}
	}

	// Clear the forwards file
	return SaveForwards(instanceDir, &ForwardsFile{Forwards: []ForwardEntry{}})
}
