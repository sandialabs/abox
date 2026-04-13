package libvirt

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/sandialabs/abox/internal/logging"
)

// Commander is an interface for executing virsh commands.
// This abstraction enables mocking virsh calls in tests.
// Note: Commands are executed directly without privilege escalation.
// Users must be in the libvirt group to run virsh commands.
type Commander interface {
	// Run executes a command and returns its stdout.
	Run(name string, args ...string) (string, error)
	// RunWithStdin executes a command with stdin input.
	RunWithStdin(name string, stdin string, args ...string) error
}

// DefaultCommander implements Commander using exec.Command.
// Users must be in the libvirt group to execute virsh commands.
type DefaultCommander struct{}

// Run executes a command and returns its stdout.
func (DefaultCommander) Run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	logging.Debug("executing command",
		"command", name,
		"args", strings.Join(args, " "),
	)

	if err := cmd.Run(); err != nil {
		logging.Debug("command failed",
			"command", name,
			"error", err.Error(),
			"stderr", stderr.String(),
		)
		return "", &CommandError{
			Command: name + " " + strings.Join(args, " "),
			Stderr:  stderr.String(),
			Err:     err,
		}
	}

	logging.Debug("command succeeded",
		"command", name,
		"stdout_len", len(stdout.String()),
	)

	return stdout.String(), nil
}

// RunWithStdin executes a command with stdin input.
func (DefaultCommander) RunWithStdin(name string, stdin string, args ...string) error {
	cmd := exec.Command(name, args...)

	cmd.Stdin = strings.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	logging.Debug("executing command with stdin",
		"command", name,
		"args", strings.Join(args, " "),
		"stdin_len", len(stdin),
	)

	if err := cmd.Run(); err != nil {
		logging.Debug("command failed",
			"command", name,
			"error", err.Error(),
			"stderr", stderr.String(),
		)
		return &CommandError{
			Command: name + " " + strings.Join(args, " "),
			Stderr:  stderr.String(),
			Err:     err,
		}
	}

	logging.Debug("command succeeded",
		"command", name,
	)

	return nil
}

// CommandError represents a command execution error with stderr context.
type CommandError struct {
	Command string
	Stderr  string
	Err     error
}

func (e *CommandError) Error() string {
	if e.Stderr != "" {
		return e.Command + " failed: " + e.Stderr + ": " + e.Err.Error()
	}
	return e.Command + " failed: " + e.Err.Error()
}

func (e *CommandError) Unwrap() error {
	return e.Err
}

// cmd is the global Commander instance.
// It defaults to DefaultCommander but can be swapped for testing.
var cmd Commander = &DefaultCommander{}

// SetCommander sets the Commander instance for test injection.
// Returns the previous Commander so it can be restored after tests.
func SetCommander(c Commander) Commander {
	prev := cmd
	cmd = c
	return prev
}

// MockCommander is a Commander implementation for testing.
type MockCommander struct {
	// RunFunc is called when Run is invoked.
	RunFunc func(name string, args ...string) (string, error)
	// RunWithStdinFunc is called when RunWithStdin is invoked.
	RunWithStdinFunc func(name string, stdin string, args ...string) error
	// Calls records all command invocations for verification.
	Calls []MockCall
}

// MockCall records a single command invocation.
type MockCall struct {
	Name  string
	Args  []string
	Stdin string
}

// Run executes the mock RunFunc or returns empty string if not set.
func (m *MockCommander) Run(name string, args ...string) (string, error) {
	m.Calls = append(m.Calls, MockCall{Name: name, Args: args})
	if m.RunFunc != nil {
		return m.RunFunc(name, args...)
	}
	return "", nil
}

// RunWithStdin executes the mock RunWithStdinFunc or returns nil if not set.
func (m *MockCommander) RunWithStdin(name string, stdin string, args ...string) error {
	m.Calls = append(m.Calls, MockCall{Name: name, Args: args, Stdin: stdin})
	if m.RunWithStdinFunc != nil {
		return m.RunWithStdinFunc(name, stdin, args...)
	}
	return nil
}
