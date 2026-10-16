package start

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/mountutil"
	fwdshared "github.com/sandialabs/abox/pkg/cmd/forward/shared"
	mountshared "github.com/sandialabs/abox/pkg/cmd/mount/shared"
)

// reconcileCalls records which seams reconcileUserResources invoked.
type reconcileCalls struct {
	unmounted    []string
	unmountForce []bool
	mounted      []string
	tunneled     []int // host ports StartTunnel was called for
}

// stubReconcileSeams replaces the reconcile seams with fakes driven by the
// given outcome functions, restoring the originals on cleanup. Matches the
// stubDaemonStarts pattern in start_test.go.
func stubReconcileSeams(t *testing.T, c *reconcileCalls,
	state func(path string) (mountutil.MountState, error),
	unmountErr, mountErr error,
	livePID func(user, ip string, entry fwdshared.ForwardEntry) (int, bool),
	tunnelPID int, tunnelErr error,
) {
	t.Helper()
	origState, origUnmount, origMount := mountStateFn, unmountFn, mountFn
	origFind, origStart := findLiveTunnelPIDFn, startTunnelFn
	t.Cleanup(func() {
		mountStateFn, unmountFn, mountFn = origState, origUnmount, origMount
		findLiveTunnelPIDFn, startTunnelFn = origFind, origStart
	})

	mountStateFn = state
	unmountFn = func(path string, force bool) error {
		c.unmounted = append(c.unmounted, path)
		c.unmountForce = append(c.unmountForce, force)
		return unmountErr
	}
	mountFn = func(paths *config.Paths, user, ip string, entry mountshared.MountEntry) error {
		c.mounted = append(c.mounted, entry.LocalPath)
		return mountErr
	}
	findLiveTunnelPIDFn = livePID
	startTunnelFn = func(paths *config.Paths, user, ip string, entry fwdshared.ForwardEntry) (int, error) {
		c.tunneled = append(c.tunneled, entry.HostPort)
		return tunnelPID, tunnelErr
	}
}

// reconcileEnv seeds a temp instance dir with one mount and one forward record
// and returns the instance, paths, and the recorded local mount path.
func reconcileEnv(t *testing.T) (*config.Instance, *config.Paths, string) {
	t.Helper()
	dir := t.TempDir()
	local := filepath.Join(dir, "mnt")
	if err := mountshared.AddMountRecord(dir, mountshared.MountEntry{
		LocalPath: local, RemotePath: "/home/dev", ReadOnly: true,
	}); err != nil {
		t.Fatalf("AddMountRecord: %v", err)
	}
	if err := fwdshared.AddForward(dir, fwdshared.ForwardEntry{
		HostPort: 8080, GuestPort: 80, PID: 1111,
	}); err != nil {
		t.Fatalf("AddForward: %v", err)
	}
	inst := &config.Instance{Name: "fcvm", IPAddress: "192.168.77.2"}
	paths := &config.Paths{Instance: dir, LogsDir: filepath.Join(dir, "logs")}
	return inst, paths, local
}

func mustMounts(t *testing.T, dir string) []mountshared.MountEntry {
	t.Helper()
	mounts, err := mountshared.GetMounts(dir)
	if err != nil {
		t.Fatalf("GetMounts: %v", err)
	}
	return mounts
}

func mustForwardPID(t *testing.T, dir string, hostPort int) int {
	t.Helper()
	entry, err := fwdshared.FindForwardByHostPort(dir, hostPort)
	if err != nil || entry == nil {
		t.Fatalf("FindForwardByHostPort(%d): entry=%v err=%v", hostPort, entry, err)
	}
	return entry.PID
}

func TestReconcileUserResources_Mounts(t *testing.T) {
	stateErr := errors.New("boom: lstat failed")
	tests := []struct {
		name        string
		state       mountutil.MountState
		stateErr    error
		unmountErr  error
		mountErr    error
		wantUnmount bool
		wantMount   bool
		wantWarn    bool
	}{
		{
			name:  "mounted is skipped",
			state: mountutil.StateMounted,
		},
		{
			name:        "stale is force-unmounted then remounted",
			state:       mountutil.StateStale,
			wantUnmount: true,
			wantMount:   true,
		},
		{
			name:        "stale unmount failure warns and skips remount",
			state:       mountutil.StateStale,
			unmountErr:  errors.New("boom: fusermount failed"),
			wantUnmount: true,
			wantWarn:    true,
		},
		{
			name:      "not mounted is remounted without unmount",
			state:     mountutil.StateNotMounted,
			wantMount: true,
		},
		{
			name:      "remount failure warns and keeps record",
			state:     mountutil.StateNotMounted,
			mountErr:  errors.New("boom: sshfs failed"),
			wantMount: true,
			wantWarn:  true,
		},
		{
			name:     "state error warns and skips",
			stateErr: stateErr,
			wantWarn: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst, paths, local := reconcileEnv(t)
			calls := &reconcileCalls{}
			stubReconcileSeams(t, calls,
				func(path string) (mountutil.MountState, error) { return tt.state, tt.stateErr },
				tt.unmountErr, tt.mountErr,
				// Forward side: tunnel alive with the recorded PID (no-op).
				func(user, ip string, entry fwdshared.ForwardEntry) (int, bool) { return entry.PID, true },
				0, nil,
			)

			var buf bytes.Buffer
			reconcileUserResources(&buf, inst, paths)

			if got := len(calls.unmounted) > 0; got != tt.wantUnmount {
				t.Errorf("unmount called = %v, want %v", got, tt.wantUnmount)
			}
			if tt.wantUnmount && len(calls.unmountForce) > 0 && !calls.unmountForce[0] {
				t.Error("stale unmount must be forced (lazy on Linux)")
			}
			if got := len(calls.mounted) > 0; got != tt.wantMount {
				t.Errorf("mount called = %v, want %v", got, tt.wantMount)
			}
			if got := strings.Contains(buf.String(), "Warning:"); got != tt.wantWarn {
				t.Errorf("warning emitted = %v, want %v; output:\n%s", got, tt.wantWarn, buf.String())
			}
			if tt.wantMount && tt.mountErr == nil && !strings.Contains(buf.String(), "Re-established mount") {
				t.Errorf("expected a Re-established message, got:\n%s", buf.String())
			}

			// The record must survive every outcome: dropping it would lose
			// user intent (mount remove is the explicit cleanup).
			mounts := mustMounts(t, paths.Instance)
			if len(mounts) != 1 || mounts[0].LocalPath != local {
				t.Errorf("mount record changed: %+v", mounts)
			}
		})
	}
}

func TestReconcileUserResources_Forwards(t *testing.T) {
	tests := []struct {
		name       string
		livePID    int
		live       bool
		tunnelPID  int
		tunnelErr  error
		wantTunnel bool
		wantPID    int
		wantWarn   bool
	}{
		{
			name:    "live tunnel with matching PID is skipped",
			livePID: 1111, live: true,
			wantPID: 1111,
		},
		{
			name:    "live tunnel under new PID updates the record",
			livePID: 2222, live: true,
			wantPID: 2222,
		},
		{
			name:       "dead tunnel is restarted and PID recorded",
			tunnelPID:  3333,
			wantTunnel: true,
			wantPID:    3333,
		},
		{
			name:       "restart failure warns and keeps the record",
			tunnelErr:  errors.New("boom: ssh failed"),
			wantTunnel: true,
			wantPID:    1111,
			wantWarn:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst, paths, _ := reconcileEnv(t)
			calls := &reconcileCalls{}
			stubReconcileSeams(t, calls,
				// Mount side: healthy (no-op).
				func(path string) (mountutil.MountState, error) { return mountutil.StateMounted, nil },
				nil, nil,
				func(user, ip string, entry fwdshared.ForwardEntry) (int, bool) { return tt.livePID, tt.live },
				tt.tunnelPID, tt.tunnelErr,
			)

			var buf bytes.Buffer
			reconcileUserResources(&buf, inst, paths)

			if got := len(calls.tunneled) > 0; got != tt.wantTunnel {
				t.Errorf("StartTunnel called = %v, want %v", got, tt.wantTunnel)
			}
			if pid := mustForwardPID(t, paths.Instance, 8080); pid != tt.wantPID {
				t.Errorf("recorded PID = %d, want %d", pid, tt.wantPID)
			}
			if got := strings.Contains(buf.String(), "Warning:"); got != tt.wantWarn {
				t.Errorf("warning emitted = %v, want %v; output:\n%s", got, tt.wantWarn, buf.String())
			}
			if tt.wantTunnel && tt.tunnelErr == nil && !strings.Contains(buf.String(), "Re-established forward") {
				t.Errorf("expected a Re-established message, got:\n%s", buf.String())
			}
		})
	}
}

// TestReconcileUserResources_FailureContinues verifies one entry's failure does
// not stop reconciliation of the remaining entries (warn-and-continue).
func TestReconcileUserResources_FailureContinues(t *testing.T) {
	inst, paths, _ := reconcileEnv(t)
	// A second mount and a second (reverse) forward after the failing first ones.
	if err := mountshared.AddMountRecord(paths.Instance, mountshared.MountEntry{
		LocalPath: filepath.Join(paths.Instance, "mnt2"), RemotePath: "/var/log",
	}); err != nil {
		t.Fatal(err)
	}
	if err := fwdshared.AddForward(paths.Instance, fwdshared.ForwardEntry{
		HostPort: 9000, GuestPort: 9001, PID: 4444, Reverse: true,
	}); err != nil {
		t.Fatal(err)
	}

	calls := &reconcileCalls{}
	stubReconcileSeams(t, calls,
		func(path string) (mountutil.MountState, error) { return mountutil.StateNotMounted, nil },
		nil, nil,
		func(user, ip string, entry fwdshared.ForwardEntry) (int, bool) { return 0, false },
		0, nil,
	)
	// First mount and first tunnel fail; the rest succeed.
	origMount, origTunnel := mountFn, startTunnelFn
	mountFn = func(paths *config.Paths, user, ip string, entry mountshared.MountEntry) error {
		if err := origMount(paths, user, ip, entry); err != nil {
			return err
		}
		if len(calls.mounted) == 1 {
			return errors.New("boom: first mount fails")
		}
		return nil
	}
	startTunnelFn = func(paths *config.Paths, user, ip string, entry fwdshared.ForwardEntry) (int, error) {
		if _, err := origTunnel(paths, user, ip, entry); err != nil {
			return 0, err
		}
		if len(calls.tunneled) == 1 {
			return 0, errors.New("boom: first tunnel fails")
		}
		return 5555, nil
	}

	var buf bytes.Buffer
	reconcileUserResources(&buf, inst, paths)

	if len(calls.mounted) != 2 {
		t.Errorf("expected both mounts attempted, got %d", len(calls.mounted))
	}
	if len(calls.tunneled) != 2 {
		t.Errorf("expected both tunnels attempted, got %d", len(calls.tunneled))
	}
	// Failed entries keep their records; the successful reverse forward gets
	// its new PID.
	if len(mustMounts(t, paths.Instance)) != 2 {
		t.Error("mount records were dropped on failure")
	}
	if pid := mustForwardPID(t, paths.Instance, 8080); pid != 1111 {
		t.Errorf("failed forward's PID changed: %d", pid)
	}
	if pid := mustForwardPID(t, paths.Instance, 9000); pid != 5555 {
		t.Errorf("reverse forward PID = %d, want 5555", pid)
	}
	if !strings.Contains(buf.String(), "Re-established reverse forward") {
		t.Errorf("expected reverse-forward message, got:\n%s", buf.String())
	}
}
