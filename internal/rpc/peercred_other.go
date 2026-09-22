//go:build !linux && !darwin

package rpc

import (
	"errors"
	"net"
)

// ErrPeerAuthUnsupported is returned by GetPeerCredentials on platforms that do
// not support SO_PEERCRED peer-credential authentication. The privileged RPC
// transport relies on this check, so callers fail closed (reject the peer)
// rather than proceeding without authentication.
var ErrPeerAuthUnsupported = errors.New("peer credential authentication is not supported on this platform")

// GetPeerCredentials always fails on non-Linux platforms. It MUST return an
// error and MUST NOT return (0, 0, nil): a zero UID would be silently treated
// as root by uidCheckListener. Returning an error makes every authenticated
// connection be rejected, which is the correct fail-closed behavior until a
// platform-native peer-auth mechanism (e.g. LOCAL_PEERCRED on darwin) is added.
func GetPeerCredentials(_ net.Conn) (pid int, uid int, err error) {
	return 0, 0, ErrPeerAuthUnsupported
}
