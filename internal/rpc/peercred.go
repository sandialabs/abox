package rpc

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// GetPeerCredentials returns the PID and UID of the peer process for a Unix socket connection.
// This uses the SO_PEERCRED socket option to get peer credentials.
func GetPeerCredentials(conn net.Conn) (pid int, uid int, err error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, errors.New("not a unix connection")
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}

	var cred *unix.Ucred
	var credErr error
	err = rawConn.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) //nolint:gosec // fd from rawConn, safe conversion
	})
	if err != nil {
		return 0, 0, err
	}
	if credErr != nil {
		return 0, 0, credErr
	}

	return int(cred.Pid), int(cred.Uid), nil
}
