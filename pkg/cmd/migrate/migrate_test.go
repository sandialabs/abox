package migrate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

// fakeEnforcer is a test double for backend.StorageEnforcer that records each
// EnsureStorageRoot call (path + regroup flag) so tests can assert the migrate
// ordering (provision before relocate, regroup after) without the privilege
// helper. An optional err makes a call fail.
type fakeEnforcer struct {
	calls []enforcerCall
	err   error
}

type enforcerCall struct {
	path    string
	regroup bool
}

func (f *fakeEnforcer) EnsureStorageRoot(_ context.Context, path string, regroup bool) error {
	f.calls = append(f.calls, enforcerCall{path: path, regroup: regroup})
	return f.err
}

// requireTools skips when the coreutils the escalate ops shell out to are absent.
// Passing tool="env" turns RunEscalated's `exec.Command(tool, args...)` into a
// direct, unprivileged exec of install/mv/chown on caller-owned temp files, so the
// real relocation logic runs hermetically without sudo.
func requireTools(t *testing.T) {
	t.Helper()
	for _, b := range []string{"env", "install", "mv", "chown"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("%s not available: %v", b, err)
		}
	}
}

func TestRelocateBaseCopiesWhenAbsent(t *testing.T) {
	requireTools(t)
	oldDir, newDir := t.TempDir(), t.TempDir()
	oldPaths := &config.Paths{BaseImages: filepath.Join(oldDir, "base")}
	newPaths := &config.Paths{BaseImages: filepath.Join(newDir, "base")}
	inst := &config.Instance{Base: "ubuntu"}

	if err := os.MkdirAll(oldPaths.BaseImages, 0o700); err != nil {
		t.Fatal(err)
	}
	oldBase := filepath.Join(oldPaths.BaseImages, "ubuntu.qcow2")
	if err := os.WriteFile(oldBase, []byte("image-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := relocateBase(&bytes.Buffer{}, "env", inst, oldPaths, newPaths)
	if err != nil {
		t.Fatalf("relocateBase: %v", err)
	}
	wantBase := filepath.Join(newPaths.BaseImages, "ubuntu.qcow2")
	if got != wantBase {
		t.Fatalf("returned base = %q, want %q", got, wantBase)
	}
	data, err := os.ReadFile(wantBase)
	if err != nil {
		t.Fatalf("copied base not readable: %v", err)
	}
	if string(data) != "image-bytes" {
		t.Fatalf("copied base contents = %q, want %q", data, "image-bytes")
	}
	// The legacy base must be left in place for other not-yet-migrated instances.
	if _, err := os.Stat(oldBase); err != nil {
		t.Errorf("legacy base should remain: %v", err)
	}
}

func TestRelocateBaseNoOpWhenPresent(t *testing.T) {
	dir := t.TempDir()
	newPaths := &config.Paths{BaseImages: filepath.Join(dir, "base")}
	if err := os.MkdirAll(newPaths.BaseImages, 0o700); err != nil {
		t.Fatal(err)
	}
	newBase := filepath.Join(newPaths.BaseImages, "ubuntu.qcow2")
	if err := os.WriteFile(newBase, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	// tool="false" would fail if any escalation ran; the no-op path must not run any.
	oldPaths := &config.Paths{BaseImages: filepath.Join(dir, "missing")}
	got, err := relocateBase(&bytes.Buffer{}, "false", &config.Instance{Base: "ubuntu"}, oldPaths, newPaths)
	if err != nil {
		t.Fatalf("relocateBase no-op: %v", err)
	}
	if got != newBase {
		t.Fatalf("returned base = %q, want %q", got, newBase)
	}
}

func TestRelocateBaseMissingOldBaseErrors(t *testing.T) {
	dir := t.TempDir()
	oldPaths := &config.Paths{BaseImages: filepath.Join(dir, "old")}
	newPaths := &config.Paths{BaseImages: filepath.Join(dir, "new")}
	if _, err := relocateBase(&bytes.Buffer{}, "false", &config.Instance{Base: "ubuntu"}, oldPaths, newPaths); err == nil {
		t.Fatal("relocateBase must error when neither old nor new base exists")
	}
}

func TestRelocateDiskMovesDir(t *testing.T) {
	requireTools(t)
	oldRoot, newRoot := t.TempDir(), t.TempDir()
	oldPaths := &config.Paths{DiskDir: filepath.Join(oldRoot, "instances", "dev")}
	newPaths := &config.Paths{DiskDir: filepath.Join(newRoot, "instances", "dev")}

	if err := os.MkdirAll(oldPaths.DiskDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldPaths.DiskDir, "disk.qcow2"), []byte("disk"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := relocateDisk(&bytes.Buffer{}, "env", oldPaths, newPaths); err != nil {
		t.Fatalf("relocateDisk: %v", err)
	}
	if _, err := os.Stat(oldPaths.DiskDir); !os.IsNotExist(err) {
		t.Error("old disk dir should be gone after move")
	}
	if data, err := os.ReadFile(filepath.Join(newPaths.DiskDir, "disk.qcow2")); err != nil || string(data) != "disk" {
		t.Fatalf("moved disk missing/incorrect: data=%q err=%v", data, err)
	}
}

func TestRelocateDiskRecoversOwnership(t *testing.T) {
	requireTools(t)
	oldRoot, newRoot := t.TempDir(), t.TempDir()
	// New exists, old does not: a prior run moved the disk but may have died before
	// chowning. relocateDisk must re-assert ownership (idempotent) and succeed
	// without disturbing the already-relocated data.
	oldPaths := &config.Paths{DiskDir: filepath.Join(oldRoot, "instances", "dev")}
	newPaths := &config.Paths{DiskDir: filepath.Join(newRoot, "instances", "dev")}
	if err := os.MkdirAll(newPaths.DiskDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newPaths.DiskDir, "disk.qcow2"), []byte("disk"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := relocateDisk(&bytes.Buffer{}, "env", oldPaths, newPaths); err != nil {
		t.Fatalf("relocateDisk recovery: %v", err)
	}
	// Recovery must preserve the relocated disk, not move/delete it.
	if data, err := os.ReadFile(filepath.Join(newPaths.DiskDir, "disk.qcow2")); err != nil || string(data) != "disk" {
		t.Fatalf("recovery disturbed relocated disk: data=%q err=%v", data, err)
	}
}

func TestRelocateDiskInterruptedErrors(t *testing.T) {
	oldRoot, newRoot := t.TempDir(), t.TempDir()
	// Both exist: an interrupted cross-fs move. relocateDisk must refuse rather than
	// risk nesting old inside new.
	oldPaths := &config.Paths{DiskDir: filepath.Join(oldRoot, "dev")}
	newPaths := &config.Paths{DiskDir: filepath.Join(newRoot, "dev")}
	for _, p := range []string{oldPaths.DiskDir, newPaths.DiskDir} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := relocateDisk(&bytes.Buffer{}, "false", oldPaths, newPaths); err == nil {
		t.Fatal("relocateDisk must refuse when both source and destination exist")
	}
}

// migFixture holds a hermetic legacy instance on disk (base + per-instance disk)
// and captures the call order / audit records as migrateOne drives the seams.
type migFixture struct {
	inst       *config.Instance
	oldPaths   *config.Paths
	newPaths   *config.Paths
	storageDir string        // destination per-user storage root (temp)
	enforcer   *fakeEnforcer // records EnsureStorageRoot calls
	calls      []string      // ordered names of the post-move seams invoked
	audits     [][]any       // AuditInstance keysAndValues per call
}

// newMigFixture sets up temp dirs with a legacy base image and disk directory,
// installs default (success) seams that route real file ops through tool="env",
// and restores every seam on cleanup. Individual tests override seams as needed.
func newMigFixture(t *testing.T) *migFixture {
	t.Helper()
	requireTools(t)

	// migrateOne now takes the shared config lock (config.AcquireLock), which
	// opens <XDG_DATA_HOME>/abox/.lock. Point it at a temp dir so the test never
	// touches the real ~/.local/share/abox — the disk paths are already isolated
	// via the seams below, but the lock path resolves independently.
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	oldRoot, newRoot := t.TempDir(), t.TempDir()
	fx := &migFixture{
		inst:       &config.Instance{Name: "dev", Base: "ubuntu", StorageDir: config.LibvirtImagesDir},
		storageDir: newRoot,
		enforcer:   &fakeEnforcer{},
		oldPaths: &config.Paths{
			BaseImages: filepath.Join(oldRoot, "base"),
			DiskDir:    filepath.Join(oldRoot, "instances", "dev"),
			Disk:       filepath.Join(oldRoot, "instances", "dev", "disk.qcow2"),
		},
		newPaths: &config.Paths{
			BaseImages:   filepath.Join(newRoot, "base"),
			DiskDir:      filepath.Join(newRoot, "instances", "dev"),
			Disk:         filepath.Join(newRoot, "instances", "dev", "disk.qcow2"),
			CloudInitISO: filepath.Join(newRoot, "instances", "dev", "cidata.iso"),
		},
	}

	// Legacy base image + per-instance disk that migrate will relocate.
	if err := os.MkdirAll(fx.oldPaths.BaseImages, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fx.oldPaths.BaseImages, "ubuntu.qcow2"), []byte("base"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fx.oldPaths.DiskDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fx.oldPaths.Disk, []byte("disk"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Save originals; restore on cleanup so tests don't leak.
	origLoad, origLegacy := migLoad, migIsLegacy
	origTool, origStop := migSelectTool, migEnsureStopped
	origRebase, origCheck, origRegroup, origSave, origAudit := migRebase, migCheck, migRegroup, migSave, migAudit
	origTarget := migStorageTarget
	t.Cleanup(func() {
		migLoad, migIsLegacy = origLoad, origLegacy
		migSelectTool, migEnsureStopped = origTool, origStop
		migRebase, migCheck, migRegroup, migSave, migAudit = origRebase, origCheck, origRegroup, origSave, origAudit
		migStorageTarget = origTarget
	})

	// Default seams: real relocation (tool="env"), real legacy check, no-op stop,
	// and success stubs for rebase/regroup/save that record their invocation order.
	// Return a fresh copy each call so a re-run reflects on-disk state (config still
	// legacy until save succeeds), matching production Load which reads from disk and
	// never shares the pointer migrateOne mutates.
	migLoad = func(string) (*config.Instance, *config.Paths, error) {
		cp := *fx.inst
		return &cp, fx.oldPaths, nil
	}
	migStorageTarget = func(*factory.Factory, string) (*storageTarget, error) {
		return &storageTarget{storageDir: fx.storageDir, paths: fx.newPaths, enforcer: fx.enforcer}, nil
	}
	migIsLegacy = config.IsLegacyStorage
	migSelectTool = func() (string, error) { return "env", nil }
	migEnsureStopped = func(*factory.Factory, string) error { return nil }
	migRebase = func(context.Context, string, string) error { fx.calls = append(fx.calls, "rebase"); return nil }
	migCheck = func(context.Context, string) error { fx.calls = append(fx.calls, "check"); return nil }
	migRegroup = func(backend.StorageEnforcer, string) error { fx.calls = append(fx.calls, "regroup"); return nil }
	migSave = func(inst *config.Instance, _ *config.Paths) error {
		fx.calls = append(fx.calls, "save")
		fx.inst = inst // capture updated StorageDir
		return nil
	}
	migAudit = func(_, _ string, kv ...any) { fx.audits = append(fx.audits, kv) }

	return fx
}

func auditStatus(kv []any) string {
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i] == "status" {
			if s, ok := kv[i+1].(string); ok {
				return s
			}
		}
	}
	return ""
}

func TestMigrateOneHappyPath(t *testing.T) {
	fx := newMigFixture(t)

	if err := migrateOne(&bytes.Buffer{}, nil, "dev"); err != nil {
		t.Fatalf("migrateOne: %v", err)
	}

	// Disk moved, base copied.
	if _, err := os.Stat(fx.oldPaths.DiskDir); !os.IsNotExist(err) {
		t.Error("old disk dir should be gone after move")
	}
	if data, err := os.ReadFile(fx.newPaths.Disk); err != nil || string(data) != "disk" {
		t.Fatalf("moved disk missing/incorrect: data=%q err=%v", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(fx.newPaths.BaseImages, "ubuntu.qcow2")); err != nil || string(data) != "base" {
		t.Fatalf("copied base missing/incorrect: data=%q err=%v", data, err)
	}

	// Post-move steps ran in order.
	if want := []string{"rebase", "check", "regroup", "save"}; !slices.Equal(fx.calls, want) {
		t.Fatalf("call order = %v, want %v", fx.calls, want)
	}
	// Two audit records: disk-relocated then complete.
	if len(fx.audits) != 2 {
		t.Fatalf("audit count = %d, want 2 (disk-relocated, complete)", len(fx.audits))
	}
	if s := auditStatus(fx.audits[0]); s != "disk-relocated" {
		t.Errorf("first audit status = %q, want disk-relocated", s)
	}
	if s := auditStatus(fx.audits[1]); s != "complete" {
		t.Errorf("second audit status = %q, want complete", s)
	}
	// Config points at the per-user storage root (not cleared) and is no longer legacy.
	if fx.inst.StorageDir != fx.storageDir {
		t.Errorf("StorageDir = %q, want %q (per-user storage root)", fx.inst.StorageDir, fx.storageDir)
	}
	if config.IsLegacyStorage(fx.inst, fx.newPaths) {
		t.Error("instance should no longer be legacy after migrate")
	}

	// migrateOne provisions the per-user root directly via the enforcer BEFORE
	// relocation (regroup=false); the post-move regroup goes through the migRegroup
	// seam (recorded as "regroup" in fx.calls above). So the enforcer itself sees
	// exactly the one provision call here.
	if len(fx.enforcer.calls) != 1 {
		t.Fatalf("enforcer calls = %d, want 1 (provision before relocation)", len(fx.enforcer.calls))
	}
	if got := fx.enforcer.calls[0]; got.path != fx.storageDir || got.regroup {
		t.Errorf("enforcer call = %+v, want provision {path:%q regroup:false}", got, fx.storageDir)
	}
}

// TestMigrateOneRequestsRegroup runs migrate with the REAL regroupStorage seam
// (not the recording stub) so the enforcer sees both the provision (regroup=false)
// and the post-move regroup (regroup=true) calls — proving migrate requests the
// privileged QEMU-group repair via EnsureStorageRoot rather than an ACL grant.
func TestMigrateOneRequestsRegroup(t *testing.T) {
	fx := newMigFixture(t)
	migRegroup = regroupStorage // use the production regroup step

	if err := migrateOne(&bytes.Buffer{}, nil, "dev"); err != nil {
		t.Fatalf("migrateOne: %v", err)
	}
	if len(fx.enforcer.calls) != 2 {
		t.Fatalf("enforcer calls = %+v, want 2 (provision + regroup)", fx.enforcer.calls)
	}
	if got := fx.enforcer.calls[0]; got.path != fx.storageDir || got.regroup {
		t.Errorf("first call = %+v, want provision {regroup:false}", got)
	}
	if got := fx.enforcer.calls[1]; got.path != fx.storageDir || !got.regroup {
		t.Errorf("second call = %+v, want regroup {regroup:true}", got)
	}
}

func TestMigrateOneRebaseFailsThenRecovers(t *testing.T) {
	fx := newMigFixture(t)

	// Rebase fails after the disk has moved.
	migRebase = func(context.Context, string, string) error {
		fx.calls = append(fx.calls, "rebase")
		return errors.New("boom")
	}

	err := migrateOne(&bytes.Buffer{}, nil, "dev")
	assertRerunHint(t, err)

	// Disk already relocated even though migration failed.
	if _, statErr := os.Stat(fx.newPaths.Disk); statErr != nil {
		t.Fatalf("disk should be relocated despite failure: %v", statErr)
	}
	// The disk-relocated audit was written before the failure.
	if len(fx.audits) != 1 || auditStatus(fx.audits[0]) != "disk-relocated" {
		t.Fatalf("expected one disk-relocated audit before failure, got %v", fx.audits)
	}
	// check/grant/save must NOT have run.
	if want := []string{"rebase"}; !slices.Equal(fx.calls, want) {
		t.Fatalf("call order = %v, want %v", fx.calls, want)
	}

	// Re-run with rebase restored to success: idempotent recovery completes.
	fx.calls = nil
	fx.audits = nil
	migRebase = func(context.Context, string, string) error { fx.calls = append(fx.calls, "rebase"); return nil }

	if err := migrateOne(&bytes.Buffer{}, nil, "dev"); err != nil {
		t.Fatalf("re-run migrateOne: %v", err)
	}
	if want := []string{"rebase", "check", "regroup", "save"}; !slices.Equal(fx.calls, want) {
		t.Fatalf("re-run call order = %v, want %v", fx.calls, want)
	}
	if fx.inst.StorageDir != fx.storageDir || config.IsLegacyStorage(fx.inst, fx.newPaths) {
		t.Error("re-run should leave config migrated")
	}
}

func TestMigrateOneSaveFailsThenRecovers(t *testing.T) {
	fx := newMigFixture(t)

	// Rebase+grant succeed; save fails.
	migSave = func(*config.Instance, *config.Paths) error {
		fx.calls = append(fx.calls, "save")
		return errors.New("write failed")
	}

	err := migrateOne(&bytes.Buffer{}, nil, "dev")
	assertRerunHint(t, err)

	// rebase+grant ran, save attempted and failed.
	if want := []string{"rebase", "check", "regroup", "save"}; !slices.Equal(fx.calls, want) {
		t.Fatalf("call order = %v, want %v", fx.calls, want)
	}
	// disk-relocated audit written; no complete audit.
	if len(fx.audits) != 1 || auditStatus(fx.audits[0]) != "disk-relocated" {
		t.Fatalf("expected one disk-relocated audit, got %v", fx.audits)
	}

	// Re-run with save restored: recovery completes.
	fx.calls = nil
	migSave = func(inst *config.Instance, _ *config.Paths) error {
		fx.calls = append(fx.calls, "save")
		fx.inst = inst
		return nil
	}
	if err := migrateOne(&bytes.Buffer{}, nil, "dev"); err != nil {
		t.Fatalf("re-run migrateOne: %v", err)
	}
	if want := []string{"rebase", "check", "regroup", "save"}; !slices.Equal(fx.calls, want) {
		t.Fatalf("re-run call order = %v, want %v", fx.calls, want)
	}
	if fx.inst.StorageDir != fx.storageDir || config.IsLegacyStorage(fx.inst, fx.newPaths) {
		t.Error("re-run should leave config migrated")
	}
}

// TestMigrateOneRebaseCheckFailsIsIncomplete proves that a rebase whose backing
// chain does not validate (e.g. the relocated base is truncated/corrupt) is
// reported as an incomplete migration rather than "complete": grant/save must
// not run, and the disk-relocated audit is the only record written.
func TestMigrateOneRebaseCheckFailsIsIncomplete(t *testing.T) {
	fx := newMigFixture(t)

	// Rebase succeeds (unsafe -u only rewrites the pointer) but validation of the
	// resulting chain fails.
	migCheck = func(context.Context, string) error {
		fx.calls = append(fx.calls, "check")
		return errors.New("Could not open backing file")
	}

	err := migrateOne(&bytes.Buffer{}, nil, "dev")
	assertRerunHint(t, err)

	// rebase+check ran; regroup/save did NOT.
	if want := []string{"rebase", "check"}; !slices.Equal(fx.calls, want) {
		t.Fatalf("call order = %v, want %v", fx.calls, want)
	}
	// Only the disk-relocated audit; no "complete".
	if len(fx.audits) != 1 || auditStatus(fx.audits[0]) != "disk-relocated" {
		t.Fatalf("expected one disk-relocated audit, got %v", fx.audits)
	}
	// Config must still record legacy storage (save never ran, so StorageDir was
	// not repointed at the per-user root).
	if fx.inst.StorageDir != config.LibvirtImagesDir {
		t.Errorf("StorageDir = %q, want unchanged (%q) when migration is incomplete", fx.inst.StorageDir, config.LibvirtImagesDir)
	}
}

// TestRelocateBaseInterruptedCopyNotAcceptedOnRerun proves the base copy is
// atomic: if a prior run was killed mid-copy, no truncated file is left at
// newBase, so a re-run re-copies from oldBase rather than accepting a partial
// image as complete. We simulate the interruption by having the copy tool write
// only part of the source, then assert that a partial dest never becomes newBase.
func TestRelocateBaseInterruptedCopyNotAcceptedOnRerun(t *testing.T) {
	requireTools(t)
	oldDir, newDir := t.TempDir(), t.TempDir()
	oldPaths := &config.Paths{BaseImages: filepath.Join(oldDir, "base")}
	newPaths := &config.Paths{BaseImages: filepath.Join(newDir, "base")}
	inst := &config.Instance{Base: "ubuntu"}

	if err := os.MkdirAll(oldPaths.BaseImages, 0o700); err != nil {
		t.Fatal(err)
	}
	oldBase := filepath.Join(oldPaths.BaseImages, "ubuntu.qcow2")
	if err := os.WriteFile(oldBase, []byte("complete-image-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	newBase := filepath.Join(newPaths.BaseImages, "ubuntu.qcow2")

	// First run: the copy "fails" (tool="false" makes CopyAsUser return an error,
	// standing in for an interruption). relocateBase must NOT leave a file at
	// newBase — the atomic temp+rename means an incomplete copy never lands there.
	if _, err := relocateBase(&bytes.Buffer{}, "false", inst, oldPaths, newPaths); err == nil {
		t.Fatal("relocateBase should error when the copy tool fails")
	}
	if _, err := os.Stat(newBase); !os.IsNotExist(err) {
		t.Fatalf("interrupted copy must not leave a file at newBase (err=%v)", err)
	}
	// No leftover temp files either.
	entries, err := os.ReadDir(newPaths.BaseImages)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("leftover temp file after interrupted copy: %s", e.Name())
		}
	}

	// Re-run with a working copy tool: because newBase was never present, the
	// re-run performs a real copy and produces a complete image.
	got, err := relocateBase(&bytes.Buffer{}, "env", inst, oldPaths, newPaths)
	if err != nil {
		t.Fatalf("re-run relocateBase: %v", err)
	}
	if got != newBase {
		t.Fatalf("returned base = %q, want %q", got, newBase)
	}
	data, err := os.ReadFile(newBase)
	if err != nil {
		t.Fatalf("re-copied base not readable: %v", err)
	}
	if string(data) != "complete-image-bytes" {
		t.Fatalf("re-copied base contents = %q, want complete image", data)
	}
}

func TestMigrateOneAlreadyMigratedNoOp(t *testing.T) {
	fx := newMigFixture(t)

	// Not legacy: short-circuit before any side-effecting seam runs.
	migIsLegacy = func(*config.Instance, *config.Paths) bool { return false }
	migSelectTool = func() (string, error) { t.Fatal("SelectEscalationTool must not run"); return "", nil }
	migEnsureStopped = func(*factory.Factory, string) error { t.Fatal("ensureStopped must not run"); return nil }
	migRebase = func(context.Context, string, string) error { t.Fatal("rebase must not run"); return nil }
	migCheck = func(context.Context, string) error { t.Fatal("check must not run"); return nil }
	migRegroup = func(backend.StorageEnforcer, string) error { t.Fatal("regroup must not run"); return nil }
	migSave = func(*config.Instance, *config.Paths) error { t.Fatal("save must not run"); return nil }
	migAudit = func(string, string, ...any) { t.Fatal("audit must not run") }

	var buf bytes.Buffer
	if err := migrateOne(&buf, nil, "dev"); err != nil {
		t.Fatalf("already-migrated migrateOne: %v", err)
	}
	if _, err := os.Stat(fx.oldPaths.DiskDir); err != nil {
		t.Error("no-op must not move the disk")
	}
	if !bytes.Contains(buf.Bytes(), []byte("already migrated")) {
		t.Errorf("expected 'already migrated' message, got %q", buf.String())
	}
}

func assertRerunHint(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	var hint *cmdutil.ErrHint
	if !errors.As(err, &hint) {
		t.Fatalf("error is not *cmdutil.ErrHint: %v", err)
	}
	if !strings.Contains(hint.Hint, "re-run") || !strings.Contains(hint.Hint, "abox migrate") {
		t.Errorf("hint should mention re-running migrate, got %q", hint.Hint)
	}
}
