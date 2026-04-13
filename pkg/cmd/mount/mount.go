package mount

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/sshutil"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// MountEntry represents a single mount record.
type MountEntry struct {
	LocalPath  string    `json:"local_path"`
	RemotePath string    `json:"remote_path"`
	MountedAt  time.Time `json:"mounted_at"`
}

// MountsFile represents the mounts.json structure.
type MountsFile struct {
	Mounts []MountEntry `json:"mounts"`
}

// Options holds the options for the mount command.
type Options struct {
	Factory    *factory.Factory
	ReadOnly   bool
	AllowOther bool
	Name       string // Instance spec (positional arg, e.g. "dev" or "dev:/var/log")
	MountPoint string // Local mount point (positional arg)
}

// NewCmdMount creates a new mount command.
func NewCmdMount(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "mount [flags] <instance>[:<remote-path>] <local-mount-point>",
		Short: "Mount an abox instance filesystem via SSHFS",
		Long: `Mount a running instance's filesystem locally using SSHFS.

The mount is recorded so it can be cleaned up with 'abox unmount'. Specify
a remote path with the instance:path syntax, or omit it to mount the home
directory.`,
		Example: `  abox mount dev ~/mnt/dev                      # mount home dir
  abox mount dev:/var/log ~/mnt/dev-logs        # specific path
  abox mount --read-only dev:/etc ~/mnt/dev-etc # read-only`,
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completion.Sequence(completion.AllInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			opts.MountPoint = args[1]
			if runF != nil {
				return runF(opts)
			}
			return opts.Run(opts.Name, opts.MountPoint)
		},
	}

	cmd.Flags().BoolVarP(&opts.ReadOnly, "read-only", "r", false, "Mount as read-only")
	cmd.Flags().BoolVarP(&opts.AllowOther, "allow-other", "o", false, "Allow other users to access the mount")

	return cmd
}

// parseInstanceSpec parses <instance>[:<path>] format.
// Returns (instance, remotePath). If no path specified, remotePath is empty.
func parseInstanceSpec(spec string) (string, string) {
	if idx := strings.Index(spec, ":"); idx > 0 {
		return spec[:idx], spec[idx+1:]
	}
	// No path specified - will default to user's home directory
	return spec, ""
}

// Run executes the mount command.
func (o *Options) Run(instanceSpec, localPath string) error {
	// Check if sshfs is installed
	if _, err := exec.LookPath("sshfs"); err != nil {
		return errors.New("sshfs not found; please install sshfs")
	}

	instanceName, remotePath := parseInstanceSpec(instanceSpec)

	factory.Ensure(&o.Factory)
	be, err := o.Factory.BackendFor(instanceName)
	if err != nil {
		return fmt.Errorf("failed to get backend: %w", err)
	}

	inst, paths, err := instance.LoadRunning(instanceName, be.VM())
	if err != nil {
		return err
	}

	// Note: SSH user is validated at config load time
	sshUser := inst.GetUser()

	// Default remote path to user's home directory
	if remotePath == "" {
		remotePath = "/home/" + sshUser
	}

	ip, err := instance.GetIP(inst, be.VM())
	if err != nil {
		return err
	}

	// Expand and resolve local path
	if strings.HasPrefix(localPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		localPath = filepath.Join(home, localPath[2:])
	}

	absLocalPath, err := filepath.Abs(localPath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	// Create mount point if needed (mode 0o700 restricts access to owner only)
	if err := os.MkdirAll(absLocalPath, 0o700); err != nil {
		return fmt.Errorf("failed to create mount point: %w", err)
	}

	// Check if already mounted
	if isMounted(absLocalPath) {
		return fmt.Errorf("path %q is already mounted", absLocalPath)
	}

	// Build sshfs command
	// Use TOFU model matching sshutil.CommonOptions
	sshfsArgs := []string{
		sshutil.RemotePath(sshUser, ip, remotePath),
		absLocalPath,
		"-o", "IdentityFile=" + paths.SSHKey,
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile=" + paths.KnownHosts,
		"-o", "LogLevel=ERROR",
	}

	if o.ReadOnly {
		sshfsArgs = append(sshfsArgs, "-o", "ro")
	}
	if o.AllowOther {
		sshfsArgs = append(sshfsArgs, "-o", "allow_other")
	}

	// Execute sshfs
	cmd := exec.Command("sshfs", sshfsArgs...)
	cmd.Stdout = o.Factory.IO.Out
	cmd.Stderr = o.Factory.IO.ErrOut

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to mount via sshfs: %w", err)
	}

	// Record mount in mounts.json
	if err := addMountRecord(paths.Instance, absLocalPath, remotePath); err != nil {
		// Mount succeeded but recording failed - warn but don't fail
		logging.Warn("failed to record mount", "error", err, "instance", instanceName)
	}

	fmt.Fprintf(o.Factory.IO.Out, "Mounted %s:%s at %s\n", instanceName, remotePath, absLocalPath)

	logging.AuditInstance(instanceName, logging.ActionMount, "local_path", absLocalPath, "remote_path", remotePath)

	return nil
}

// isMounted checks if a path is a mount point.
func isMounted(path string) bool {
	cmd := exec.Command("mountpoint", "-q", path)
	return cmd.Run() == nil
}

// getMountsFilePath returns the path to mounts.json for an instance.
func getMountsFilePath(instanceDir string) string {
	return filepath.Join(instanceDir, "mounts.json")
}

// loadMounts loads the mounts file for an instance.
func loadMounts(instanceDir string) (*MountsFile, error) {
	path := getMountsFilePath(instanceDir)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &MountsFile{Mounts: []MountEntry{}}, nil
	}
	if err != nil {
		return nil, err
	}

	var mounts MountsFile
	if err := json.Unmarshal(data, &mounts); err != nil {
		return nil, err
	}
	return &mounts, nil
}

// saveMounts saves the mounts file for an instance.
func saveMounts(instanceDir string, mounts *MountsFile) error {
	path := getMountsFilePath(instanceDir)
	data, err := json.MarshalIndent(mounts, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// addMountRecord adds a mount to the mounts file.
func addMountRecord(instanceDir, localPath, remotePath string) error {
	mounts, err := loadMounts(instanceDir)
	if err != nil {
		return err
	}

	mounts.Mounts = append(mounts.Mounts, MountEntry{
		LocalPath:  localPath,
		RemotePath: remotePath,
		MountedAt:  time.Now(),
	})

	return saveMounts(instanceDir, mounts)
}

// RemoveMountRecord removes a mount from the mounts file (exported for unmount command).
func RemoveMountRecord(instanceDir, localPath string) error {
	mounts, err := loadMounts(instanceDir)
	if err != nil {
		return err
	}

	filtered := make([]MountEntry, 0, len(mounts.Mounts))
	for _, m := range mounts.Mounts {
		if m.LocalPath != localPath {
			filtered = append(filtered, m)
		}
	}
	mounts.Mounts = filtered

	return saveMounts(instanceDir, mounts)
}

// GetMounts returns all mounts for an instance (exported for unmount command).
func GetMounts(instanceDir string) ([]MountEntry, error) {
	mounts, err := loadMounts(instanceDir)
	if err != nil {
		return nil, err
	}
	return mounts.Mounts, nil
}
