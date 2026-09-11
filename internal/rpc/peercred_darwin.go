//go:build darwin

package rpc

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// xucredVersion0 is the current version of the xucred structure returned by
// LOCAL_PEERCRED on macOS. It corresponds to XUCRED_VERSION from
// <sys/ucred.h>, which golang.org/x/sys/unix does not export as a constant.
// The kernel stamps this into the Version field; we refuse to trust the UID
// unless it matches exactly (fail closed).
const xucredVersion0 = 0

// validateXucred converts a peer xucred (version, uid) into a trusted UID.
// It fails closed: if the kernel-reported structure version does not match the
// version we compiled against, the UID cannot be trusted and an error is
// returned instead. This mirrors the fail-closed contract of the other
// platform implementations, where an unauthenticated peer must be rejected
// rather than silently treated as uid 0 (root).
func validateXucred(version uint32, uid uint32) (int, error) {
	if version != xucredVersion0 {
		return 0, fmt.Errorf("unexpected xucred version %d (want %d); refusing to trust peer uid", version, xucredVersion0)
	}
	return int(uid), nil
}

// GetPeerCredentials returns the PID and UID of the peer process for a Unix
// socket connection. On macOS this uses the LOCAL_PEERCRED socket option to
// retrieve peer credentials via Xucred.
//
// macOS LOCAL_PEERCRED does not report the peer PID, so pid is always 0. The
// UID is only returned after validateXucred confirms the structure version, so
// a version mismatch fails closed rather than trusting an unverified UID.
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
		xucred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	})
	if err != nil {
		return 0, 0, err
	}
	if credErr != nil {
		return 0, 0, credErr
	}

	validUID, err := validateXucred(xucred.Version, xucred.Uid)
	if err != nil {
		return 0, 0, err
	}

	// macOS LOCAL_PEERCRED provides no peer PID; return 0.
	return 0, validUID, nil
}
