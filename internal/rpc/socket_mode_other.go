//go:build !darwin

package rpc

import "os"

// socketPeerCheckMode is the mode applied to the privilege-helper socket on
// Linux (and any non-darwin platform). It is 0o666: the socket is created by the
// root-owned helper, the non-root client must connect, and chown-at-creation
// would require knowing the client UID up front. Security is enforced via the
// SO_PEERCRED kernel UID check plus the auth token (see UnixListenWithUIDCheck).
const socketPeerCheckMode os.FileMode = 0o666
