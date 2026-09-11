//go:build darwin

package config

// maxUnixSocketPathLen is the maximum usable length of a unix-domain socket path
// on macOS. sockaddr_un.sun_path is 104 bytes including the NUL terminator, so
// 103 bytes are usable; net.Listen("unix", …) fails with "invalid argument"
// beyond that. Per-instance sockets live under $TMPDIR (a long
// /var/folders/xx/…/T/ path), so a long instance name can overflow this.
const maxUnixSocketPathLen = 103
