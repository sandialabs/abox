//go:build !unix

package sysutil

import "os"

// FileOwner cannot determine POSIX file ownership on non-unix platforms
// (notably Windows), where os.FileInfo.Sys() does not carry a uid/gid. It always
// returns ok=false. This is the fail-closed contract: callers that make a
// security or permission decision from ownership must treat ok=false as
// "ownership unknown" and refuse rather than assume the file is owned by the
// caller. A native implementation would require Windows SID handling and belongs
// alongside a Windows VM backend, which does not exist yet.
func FileOwner(_ os.FileInfo) (uid, gid int, ok bool) {
	return 0, 0, false
}
