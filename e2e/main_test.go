//go:build e2e

package e2e

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/pkg/cmd/factory"
)

var (
	helperCmd    *exec.Cmd
	helperSocket string
	helperToken  string
)

// TestMain sets up a shared privilege helper for all e2e tests.
// This results in a single sudo prompt at the start of the test run
// instead of one prompt per test.
func TestMain(m *testing.M) {
	// Skip helper setup if not running tests
	if os.Getenv("GO_TEST_SHORT") != "" {
		os.Exit(m.Run())
	}

	if err := checkBinaryFreshness(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	if err := startSharedHelper(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start shared privilege helper: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	stopSharedHelper()
	os.Exit(code)
}

// startSharedHelper starts the privilege helper and sets env vars for abox to use.
func startSharedHelper() error {
	// If an external helper is already provided (e.g., by e2e/matrix runner),
	// reuse it instead of starting a new one.
	if os.Getenv(factory.EnvPrivilegeSocket) != "" && os.Getenv(factory.EnvPrivilegeToken) != "" {
		fmt.Fprintln(os.Stderr, "Using external privilege helper")
		return nil
	}

	// Find abox binary
	aboxPath, err := findAboxBinary()
	if err != nil {
		return fmt.Errorf("abox binary not found: %w", err)
	}

	// Generate auth token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}
	helperToken = hex.EncodeToString(tokenBytes)

	// Generate socket path
	socketDir := config.RuntimeDirOr(os.TempDir())
	helperSocket = filepath.Join(socketDir, fmt.Sprintf("abox-e2e-%d.sock", os.Getpid()))

	// Remove stale socket
	os.Remove(helperSocket)

	// Build command with sudo
	helperCmd = exec.Command("sudo", aboxPath, "privilege-helper",
		"--socket", helperSocket,
		"--allowed-uid", strconv.Itoa(os.Getuid()))

	// Set up stdin pipe for token
	stdin, err := helperCmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	helperCmd.Stderr = os.Stderr

	fmt.Fprintln(os.Stderr, "Starting shared privilege helper (single sudo prompt for all e2e tests)...")

	if err := helperCmd.Start(); err != nil {
		return fmt.Errorf("failed to start helper: %w", err)
	}

	// Send token via stdin
	if _, err := io.WriteString(stdin, helperToken+"\n"); err != nil {
		helperCmd.Process.Kill()
		helperCmd.Wait()
		return fmt.Errorf("failed to send token: %w", err)
	}
	stdin.Close()

	// Wait for socket to appear (allow time for sudo prompt)
	if err := waitForSocket(helperSocket, 60*time.Second); err != nil {
		helperCmd.Process.Kill()
		helperCmd.Wait()
		return err
	}

	// Set environment variables so abox uses this helper
	os.Setenv(factory.EnvPrivilegeSocket, helperSocket)
	os.Setenv(factory.EnvPrivilegeToken, helperToken)

	fmt.Fprintln(os.Stderr, "Shared privilege helper started successfully")
	return nil
}

// stopSharedHelper stops the shared privilege helper.
func stopSharedHelper() {
	// Clear environment variables
	os.Unsetenv(factory.EnvPrivilegeSocket)
	os.Unsetenv(factory.EnvPrivilegeToken)

	if helperCmd == nil || helperCmd.Process == nil {
		return
	}

	// Try graceful shutdown first
	helperCmd.Process.Signal(syscall.SIGTERM)

	// Wait for process with timeout
	done := make(chan error, 1)
	go func() {
		done <- helperCmd.Wait()
	}()

	select {
	case <-done:
		// Process exited
	case <-time.After(5 * time.Second):
		// Force kill if it didn't exit
		helperCmd.Process.Kill()
		<-done
	}

	// Clean up socket
	os.Remove(helperSocket)
}

// findAboxBinary finds the abox binary for e2e tests.
func findAboxBinary() (string, error) {
	candidates := []string{
		"./abox",
		"../abox",
		filepath.Join(os.Getenv("HOME"), ".local/bin/abox"),
	}

	for _, candidate := range candidates {
		absPath, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		if info, err := os.Stat(absPath); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return absPath, nil
		}
	}

	return "", fmt.Errorf("abox binary not found in: %v", candidates)
}

// waitForSocket waits for a socket file to appear.
func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for socket %s", path)
}

// checkBinaryFreshness fails fast if the abox binary is older than any source file.
// This prevents wasting a 30-minute e2e run on a stale binary.
func checkBinaryFreshness() error {
	binPath, err := filepath.Abs("../abox")
	if err != nil {
		return nil // can't check, skip
	}
	binInfo, err := os.Stat(binPath)
	if err != nil {
		return nil // binary doesn't exist yet, findAboxBinary will handle
	}
	binTime := binInfo.ModTime()

	repoRoot, err := filepath.Abs("..")
	if err != nil {
		return nil
	}

	var newestTime time.Time
	var newestFile string
	filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules", "e2e":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.ModTime().After(newestTime) {
			newestTime = info.ModTime()
			newestFile, _ = filepath.Rel(repoRoot, path)
		}
		return nil
	})

	if newestTime.After(binTime) {
		return fmt.Errorf(
			"abox binary is stale: %s modified %s, but binary built %s\n"+
				"Run 'make build' or use 'make test-e2e' which rebuilds automatically",
			newestFile,
			newestTime.Format("2006-01-02 15:04:05"),
			binTime.Format("2006-01-02 15:04:05"),
		)
	}
	return nil
}
