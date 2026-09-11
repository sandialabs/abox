// Package migrate implements `abox migrate`, a one-time tool that moves an
// instance's disk storage from the legacy monolithic root-owned location
// (/var/lib/libvirt/images/abox, shared across users) into the caller's per-user
// storage root (/var/lib/libvirt/images/abox/<uid>) used by the group-owned
// storage model. It performs one privileged step — relocating the root-owned
// files (via a one-shot sudo/pkexec) — and then, through the privilege helper,
// provisions the per-user root (owned by the caller, setgid to the QEMU group)
// and re-groups the relocated files so the VM process can read them; everything
// else runs unprivileged.
//
// Transitional: this command and its companion legacy gate
// (internal/instance/legacy.go) exist only to migrate pre-per-user-storage
// instances. Once no supported deployment still has legacy root-owned instances,
// both should be removed.
package migrate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/privilege"
	"github.com/sandialabs/abox/internal/qemuimg"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

// Options holds the options for the migrate command.
type Options struct {
	Factory *factory.Factory
	All     bool
	Names   []string
}

// Package-level function seams for the side-effecting steps of migrateOne, so
// tests can substitute them. Production keeps the real implementations; tests
// inject failures to exercise the ordering and interruption-window recovery
// behavior. See migrate_test.go.
var (
	migLoad          = config.Load
	migIsLegacy      = config.IsLegacyStorage
	migSelectTool    = privilege.SelectEscalationTool
	migEnsureStopped = ensureStopped
	migRebase        = qemuimg.Rebase
	migCheck         = qemuimg.Check
	migRegroup       = regroupStorage
	migSave          = config.Save
	migAudit         = logging.AuditInstance

	// migStorageTarget resolves the destination storage dir and the paths under
	// it for an instance (the backend's per-user storage root; see create.go). It
	// also yields the privileged storage enforcer used to provision + regroup that
	// root. A seam so tests can supply a temp destination and a fake enforcer
	// without a backend or the privilege helper.
	migStorageTarget = defaultStorageTarget
)

// storageTarget is the migration destination for one instance: the backend's
// per-user storage root, the instance paths computed under it, and the
// privileged enforcer that provisions + regroups that root.
type storageTarget struct {
	storageDir string
	paths      *config.Paths
	enforcer   backend.StorageEnforcer
}

// defaultStorageTarget resolves the real destination via the factory: the
// backend's StorageDir (the per-user root, mirroring create.go) and a storage
// enforcer backed by the privilege helper.
func defaultStorageTarget(f *factory.Factory, name string) (*storageTarget, error) {
	be, err := f.BackendFor(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get backend: %w", err)
	}
	storageDir := be.StorageDir()
	paths, err := config.GetPathsWithStorage(name, storageDir)
	if err != nil {
		return nil, err
	}
	enforcer, err := f.StorageEnforcerFor(name)
	if err != nil {
		return nil, err
	}
	return &storageTarget{storageDir: storageDir, paths: paths, enforcer: enforcer}, nil
}

// regroupStorage provisions the caller's per-user storage root and re-groups the
// just-relocated files to the QEMU group (the privileged, helper-side step; see
// backend.StorageEnforcer.EnsureStorageRoot). This replaces the old ACL grant:
// MoveAsUser/ChownRecursiveAsUser chowned the relocated files to the caller's
// PRIMARY group, losing the QEMU group, so the helper walks the caller's own
// subtree and restores it. Idempotent.
func regroupStorage(enforcer backend.StorageEnforcer, storageDir string) error {
	return enforcer.EnsureStorageRoot(context.Background(), storageDir, true)
}

// NewCmdMigrate creates the migrate command.
func NewCmdMigrate(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:   "migrate [name...]",
		Short: "Migrate instances from legacy root-owned disk storage",
		Long: `Move an instance's disk image from the legacy monolithic root-owned
location (/var/lib/libvirt/images/abox) into your per-user storage root
(/var/lib/libvirt/images/abox/<uid>).

Instances created before disk storage moved to the group-owned per-user model
keep their image in a shared root-owned directory that abox can no longer manage
unprivileged. This one-time migration relocates the image (the step that needs
sudo), rebases it onto the relocated base image, and — via the privilege helper —
provisions your per-user storage root and re-groups the relocated files to the
QEMU runtime group so the VM process can read them.

The instance must be stopped before migrating.`,
		Example: `  abox migrate dev                         # Migrate one instance
  abox migrate dev staging                 # Migrate multiple instances
  abox migrate --all                       # Migrate every legacy instance`,
		ValidArgsFunction: completion.Repeat(completion.AllInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Names = args
			if runF != nil {
				return runF(opts)
			}
			return run(opts)
		},
	}

	cmd.Flags().BoolVar(&opts.All, "all", false, "Migrate every instance still using legacy storage")
	return cmd
}

// Run executes the migrate command with the given options.
func Run(opts *Options) error {
	factory.Ensure(&opts.Factory)
	return run(opts)
}

func run(opts *Options) error {
	factory.Ensure(&opts.Factory)
	w := opts.Factory.IO.Out

	names := opts.Names
	if opts.All {
		all, err := legacyInstances()
		if err != nil {
			return err
		}
		if len(all) == 0 {
			fmt.Fprintln(w, "No instances are using legacy storage.")
			return nil
		}
		names = all
	}
	if len(names) == 0 {
		return &cmdutil.ErrHint{
			Err:  errors.New("no instances specified"),
			Hint: "pass instance names, or use --all to migrate every legacy instance",
		}
	}

	return cmdutil.ForEach(names, func(name string) error {
		return migrateOne(w, opts.Factory, name)
	})
}

// legacyInstances returns the names of all instances still using legacy storage.
func legacyInstances() ([]string, error) {
	all, err := config.List()
	if err != nil {
		return nil, err
	}
	var legacy []string
	for _, name := range all {
		inst, paths, err := config.Load(name)
		if err != nil {
			logging.Warn("skipping unreadable instance during migrate scan", "instance", name, "error", err)
			continue
		}
		if config.IsLegacyStorage(inst, paths) {
			legacy = append(legacy, name)
		}
	}
	return legacy, nil
}

func migrateOne(w io.Writer, f *factory.Factory, name string) error {
	inst, oldPaths, err := migLoad(name)
	if err != nil {
		return err
	}
	if !migIsLegacy(inst, oldPaths) {
		fmt.Fprintf(w, "Instance %q is already migrated.\n", name)
		return nil
	}

	// Acquire the shared config lock for the mutating span (like create/remove/
	// start/import): it must cover the ensureStopped check through the final
	// config.Save so a concurrent start/remove can't race the TOCTOU window
	// between "verified stopped" and "files relocated + config pointed anew".
	if err := config.AcquireLock(); err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = config.ReleaseLock() }()

	if err := migEnsureStopped(f, name); err != nil {
		return err
	}

	// Destination: the backend's per-user storage root and the paths under it
	// (mirroring create.go), plus the privileged enforcer that provisions and
	// re-groups that root.
	target, err := migStorageTarget(f, name)
	if err != nil {
		return err
	}
	newPaths := target.paths
	tool, err := migSelectTool()
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "Migrating %q from %s ...\n", name, config.LibvirtImagesDir)

	// Provision the per-user storage root FIRST (owned by the caller, setgid to
	// the QEMU group). The legacy parent is root-owned, so the unprivileged
	// relocation below could not otherwise create the caller's subtree under it.
	if err := target.enforcer.EnsureStorageRoot(context.Background(), target.storageDir, false); err != nil {
		return fmt.Errorf("failed to prepare storage root: %w", err)
	}

	newBase, err := relocateBase(w, tool, inst, oldPaths, newPaths)
	if err != nil {
		return err
	}
	if err := relocateDisk(w, tool, oldPaths, newPaths); err != nil {
		return err
	}

	// The disk has physically moved. Audit that immediately: from here on the
	// on-disk state diverges from the recorded config, so even if a post-move
	// step below fails, the partial migration is always in the audit trail. A
	// successful completion writes a second "complete" record below.
	migAudit(name, "migrate", "status", "disk-relocated", "from", config.LibvirtImagesDir, "to", filepath.Dir(newPaths.DiskDir))

	// Rebase the disk's backing pointer onto the relocated base (unprivileged now
	// that the files are user-owned), re-group the relocated files to the QEMU
	// group (the privileged helper step — the relocation chowned them to the
	// caller's primary group, losing the QEMU group), then point the instance
	// config at the per-user storage.
	//
	// If any of these post-move steps fails, the disk is already relocated but the
	// config still records legacy storage. We do NOT roll back: relocateBase copies
	// (never moves) the base and relocateDisk's re-run logic re-asserts ownership on
	// the already-moved disk, so simply re-running migrate is safe and idempotent.
	// Wrap the failure with that guidance.
	if err := migRebase(context.Background(), newPaths.Disk, newBase); err != nil {
		return incompleteMigration(name, fmt.Errorf("failed to rebase disk: %w", err))
	}
	// Rebase is unsafe (-u): it rewrites only the backing pointer without opening
	// the new backing file. Validate the resulting chain actually opens so a
	// truncated/corrupt base is caught here rather than at boot.
	if err := migCheck(context.Background(), newPaths.Disk); err != nil {
		return incompleteMigration(name, fmt.Errorf("rebased disk failed validation: %w", err))
	}
	if err := migRegroup(target.enforcer, target.storageDir); err != nil {
		return incompleteMigration(name, fmt.Errorf("failed to re-group relocated files for the QEMU user: %w", err))
	}

	// Point the instance at its per-user storage root so Load resolves there.
	inst.StorageDir = target.storageDir
	if err := migSave(inst, newPaths); err != nil {
		return incompleteMigration(name, fmt.Errorf("failed to update instance config: %w", err))
	}

	migAudit(name, "migrate", "status", "complete", "from", config.LibvirtImagesDir, "to", filepath.Dir(newPaths.DiskDir))
	fmt.Fprintf(w, "Instance %q migrated to %s.\n", name, newPaths.DiskDir)
	return nil
}

// incompleteMigration wraps a post-move failure with guidance: the disk has been
// relocated but migration did not finish, and re-running migrate is safe and will
// complete it (the copy-not-move base + idempotent relocateDisk make re-runs safe).
func incompleteMigration(name string, err error) error {
	return &cmdutil.ErrHint{
		Err:  fmt.Errorf("migration of %q is incomplete: %w", name, err),
		Hint: fmt.Sprintf("the disk was moved but migration did not finish; re-run to complete it: abox migrate %q", name),
	}
}

// ensureStopped errors unless the instance's VM is stopped (we are moving the
// files it boots from).
func ensureStopped(f *factory.Factory, name string) error {
	be, err := f.BackendFor(name)
	if err != nil {
		return fmt.Errorf("failed to get backend: %w", err)
	}
	if be.VM().IsRunning(name) {
		return &cmdutil.ErrHint{
			Err:  fmt.Errorf("instance %q is running", name),
			Hint: "stop it first: abox stop " + name,
		}
	}
	return nil
}

// relocateBase copies the (shared) base image into the new storage location and
// returns its new path. It COPIES rather than moves, leaving the legacy base in
// place so any not-yet-migrated instance that shares it still works. It is a
// no-op when the base is already present in the new location.
func relocateBase(w io.Writer, tool string, inst *config.Instance, oldPaths, newPaths *config.Paths) (string, error) {
	oldBase := filepath.Join(oldPaths.BaseImages, config.UserBaseImageName(inst.Base))
	newBase := filepath.Join(newPaths.BaseImages, config.UserBaseImageName(inst.Base))
	if _, err := os.Stat(newBase); err == nil {
		return newBase, nil
	}
	if _, err := os.Stat(oldBase); err != nil {
		return "", &cmdutil.ErrHint{
			Err:  fmt.Errorf("base image %q not found at %s", inst.Base, oldBase),
			Hint: "after migrating, pull it with: abox base pull " + inst.Base,
		}
	}
	if err := os.MkdirAll(newPaths.BaseImages, 0o700); err != nil {
		return "", fmt.Errorf("failed to create base images directory: %w", err)
	}
	fmt.Fprintf(w, "  copying base image %q ...\n", inst.Base)
	// CopyAsUser (install) is a non-atomic in-place write: if migrate is killed
	// mid-copy, a truncated file would remain at newBase and the early os.Stat
	// check above would wrongly treat it as complete on re-run. Copy into a unique
	// temp path in the destination directory, then atomically rename into place, so
	// newBase only ever exists once the copy has fully succeeded. The rename is
	// within the user-owned dest dir, so it needs no extra escalation.
	tmp, err := os.CreateTemp(newPaths.BaseImages, config.UserBaseImageName(inst.Base)+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp base image: %w", err)
	}
	tmpPath := tmp.Name()
	// We only need the unique name; install overwrites the file, so close it now.
	tmp.Close()
	// Best-effort cleanup on any failure before the rename; a no-op afterward.
	defer os.Remove(tmpPath)
	if err := privilege.CopyAsUser(tool, oldBase, tmpPath); err != nil {
		return "", fmt.Errorf("failed to copy base image: %w", err)
	}
	if err := os.Rename(tmpPath, newBase); err != nil {
		return "", fmt.Errorf("failed to finalize base image: %w", err)
	}
	return newBase, nil
}

// relocateDisk moves the per-instance disk directory (disk.qcow2 + cidata.iso)
// into the new storage location. It is recoverable: a re-run after an interrupted
// migration re-asserts ownership on an already-moved disk instead of failing.
func relocateDisk(w io.Writer, tool string, oldPaths, newPaths *config.Paths) error {
	_, newErr := os.Stat(newPaths.DiskDir)
	_, oldErr := os.Stat(oldPaths.DiskDir)
	newExists := newErr == nil
	oldExists := oldErr == nil

	switch {
	case newExists && !oldExists:
		// A prior run moved the disk but may have failed before/after chowning it.
		// Re-assert ownership (idempotent) rather than trying to move again.
		fmt.Fprintln(w, "  disk already relocated; ensuring ownership ...")
		if err := privilege.ChownRecursiveAsUser(tool, newPaths.DiskDir); err != nil {
			return fmt.Errorf("failed to set disk ownership: %w", err)
		}
		return nil
	case newExists && oldExists:
		// Both locations exist: a previous cross-filesystem move was interrupted,
		// leaving a partial copy at the destination. Refuse to guess (moving again
		// would nest old inside new); tell the user how to recover.
		return &cmdutil.ErrHint{
			Err:  fmt.Errorf("a previous migration of %q was interrupted; partial data exists at %s", filepath.Base(newPaths.DiskDir), newPaths.DiskDir),
			Hint: "remove the partial destination and re-run migrate: sudo rm -rf " + newPaths.DiskDir,
		}
	}

	if err := os.MkdirAll(filepath.Dir(newPaths.DiskDir), 0o700); err != nil {
		return fmt.Errorf("failed to create storage directory: %w", err)
	}
	fmt.Fprintln(w, "  moving disk ...")
	if err := privilege.MoveAsUser(tool, oldPaths.DiskDir, newPaths.DiskDir); err != nil {
		return fmt.Errorf("failed to move disk: %w", err)
	}
	return nil
}
