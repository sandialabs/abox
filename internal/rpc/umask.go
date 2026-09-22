package rpc

import (
	"net"

	"github.com/sandialabs/abox/internal/sysutil"
)

// listenUnixRestrictive creates a Unix-domain socket listener with a restrictive
// umask (0o077 via sysutil.WithRestrictiveUmask) so the socket is created mode
// 0o600. Callers that need a different mode (e.g. the root-owned helper socket)
// chmod afterward. On platforms without a umask the helper simply runs the
// listen (see sysutil.WithRestrictiveUmask); the privileged transport is not
// usable there anyway because peer-credential auth is unsupported.
func listenUnixRestrictive(path string) (net.Listener, error) {
	var listener net.Listener
	var err error
	sysutil.WithRestrictiveUmask(func() {
		listener, err = net.Listen("unix", path)
	})
	return listener, err
}
