//go:build unix

package procutil

import "syscall"

// Exec replaces the current process image with the program at argv0, passing
// argv (argv[0] should be the program name) and env. On success it does not
// return — the calling process is replaced. On unix this is syscall.Exec, so the
// exit status, signals, and terminal are inherited directly by the replacement.
func Exec(argv0 string, argv []string, env []string) error {
	return syscall.Exec(argv0, argv, env)
}
