//go:build darwin

package rpc

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// GetPeerCredentials returns the PID and UID of the peer process for a Unix socket connection.
// On macOS, this uses the LOCAL_PEERCRED socket option to get peer credentials via Xucred.
func GetPeerCredentials(conn net.Conn) (pid int, uid int, err error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, errors.New("not a unix connection")
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}

	var xucred *unix.Xucred
	var credErr error
	err = rawConn.Control(func(fd uintptr) {
		xucred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED) //nolint:gosec // fd from rawConn, safe conversion
	})
	if err != nil {
		return 0, 0, err
	}
	if credErr != nil {
		return 0, 0, credErr
	}

	return 0, int(xucred.Uid), nil
}
