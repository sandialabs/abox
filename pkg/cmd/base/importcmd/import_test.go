package importcmd

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunImportRejectsUnsafeVMDK asserts base import rejects a VMDK whose
// plain-text descriptor points a FLAT extent at an absolute host path
// (e.g. /etc/shadow) BEFORE handing it to qemu-img convert, which would
// otherwise fold that host file into the base image. The rejection surfaces the
// "not self-contained" guard rather than an opaque qemu-img error.
func TestRunImportRejectsUnsafeVMDK(t *testing.T) {
	// Drive config.GetPaths("") at a hermetic location via XDG_DATA_HOME, and
	// isolate the staging runtime dir so it succeeds under a restricted or absent
	// /run/user (the staging via config.RuntimeDir() runs before the guard).
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	// A plain-text VMDK descriptor with an absolute FLAT extent path.
	src := filepath.Join(t.TempDir(), "evil.vmdk")
	desc := "# Disk DescriptorFile\n" +
		"version=1\n" +
		"CID=fffffffe\n" +
		"parentCID=ffffffff\n" +
		"createType=\"monolithicFlat\"\n" +
		"RW 12345 FLAT \"/etc/shadow\" 0\n"
	if err := os.WriteFile(src, []byte(desc), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runImport(context.Background(), io.Discard, "evil", src)
	if err == nil {
		t.Fatal("expected base import to reject a VMDK with an absolute extent path")
	}
	if !strings.Contains(err.Error(), "self-contained") {
		t.Errorf("error should surface the self-containment guard, got: %v", err)
	}

	// The conversion must not have run: no base image should have been written.
	_ = filepath.WalkDir(dataHome, func(path string, _ os.DirEntry, _ error) error {
		if strings.HasSuffix(path, "evil.qcow2") {
			t.Errorf("base image was written despite rejection: %s", path)
		}
		return nil
	})
}

// TestRunImportRejectsVMDKParentPointer asserts a VMDK naming a parent
// (parentFileNameHint) is likewise rejected as not self-contained.
func TestRunImportRejectsVMDKParentPointer(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	src := filepath.Join(t.TempDir(), "child.vmdk")
	desc := "# Disk DescriptorFile\n" +
		"version=1\n" +
		"parentCID=deadbeef\n" +
		"parentFileNameHint=\"/some/base.vmdk\"\n" +
		"createType=\"monolithicSparse\"\n"
	if err := os.WriteFile(src, []byte(desc), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runImport(context.Background(), io.Discard, "child", src)
	if err == nil {
		t.Fatal("expected base import to reject a child/linked VMDK")
	}
	if !strings.Contains(err.Error(), "self-contained") {
		t.Errorf("error should surface the self-containment guard, got: %v", err)
	}
}
