//go:build !darwin

package config

// maxUnixSocketPathLen is 0 (no check) off macOS. Linux allows a 108-byte
// sun_path and the default runtime dir (/run/user/<uid>) is short, so abox's
// per-instance socket paths do not approach the limit in normal use;
// ValidateSocketPaths is a no-op.
//
// Known limitation (deliberately not guarded): a user-set, unusually long
// XDG_RUNTIME_DIR combined with a 63-char instance name could still exceed 108
// bytes and make net.Listen("unix", …) fail with an opaque "invalid argument".
// We do NOT enforce a Linux bound here because a strict check would also reject
// the legitimately-long temp paths used by hermetic tests and CI (t.TempDir()),
// where no socket is ever bound. macOS is guarded because its default $TMPDIR is
// itself long and its sun_path is only 104 bytes.
const maxUnixSocketPathLen = 0
