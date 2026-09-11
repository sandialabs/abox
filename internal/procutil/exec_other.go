//go:build !unix

package procutil

import (
	"errors"
	"os"
	"os/exec"
)

// Exec emulates exec-replacement on platforms without execve (Windows): it runs
// argv0 as a child process, forwarding stdio, waits for it, and propagates the
// child's exit code by calling os.Exit. It only returns an error if the child
// could not be started; on a clean or non-zero child exit it terminates this
// process with the same code, matching the observable behavior of the unix
// syscall.Exec path (the ssh/scp callers expect the process to end here).
func Exec(argv0 string, argv []string, env []string) error {
	args := []string{}
	if len(argv) > 1 {
		args = argv[1:]
	}
	// argv is the resolved ssh/scp invocation, same as the unix path.
	cmd := exec.Command(argv0, args...)
	cmd.Args = argv
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	os.Exit(0)
	return nil // unreachable
}
