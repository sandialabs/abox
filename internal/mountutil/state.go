package mountutil

// MountState is the tri-state result of State: unlike IsMounted (which folds a
// dead FUSE endpoint into "mounted" for the unmount commands), it lets callers
// that want to REPAIR a mount distinguish a healthy mount from a stale one.
type MountState int

const (
	// StateNotMounted means path is not a mount point (or does not exist).
	StateNotMounted MountState = iota
	// StateMounted means path is a live mount point on a distinct device.
	StateMounted
	// StateStale means path is a FUSE/SSHFS mount whose server has died: the
	// mount still exists in the kernel mount table but stat'ing it fails with
	// ENOTCONN ("transport endpoint is not connected"). It must be unmounted
	// (force/lazy) before the path can be mounted again.
	StateStale
)
