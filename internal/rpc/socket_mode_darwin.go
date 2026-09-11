//go:build darwin

package rpc

import "os"

// socketPeerCheckMode is the mode applied to the privilege-helper socket on
// darwin. The spawn path knows the allowed UID and chowns the socket to it, so
// the mode is tightened to 0o600 (owner-only) rather than the 0o666 used on
// Linux. Combined with the chown, only the client user can connect.
const socketPeerCheckMode os.FileMode = 0o600
