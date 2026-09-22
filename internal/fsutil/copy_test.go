package fsutil

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCopyFileFailedCopyLeavesNoDst(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")

	if err := os.WriteFile(src, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Force the buffered fallback (defeat reflink) and make it fail mid-copy.
	prevReflink, prevCopy := reflink, copyContents
	reflink = func(_, _ *os.File) error { return errors.New("no reflink") }
	copyContents = func(io.Writer, io.Reader) error { return errors.New("boom") }
	t.Cleanup(func() { reflink, copyContents = prevReflink, prevCopy })

	if err := CopyFile(src, dst); err == nil {
		t.Fatal("CopyFile must return the forced copy error")
	}

	// The destination must not exist (atomic rename never happened).
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Errorf("dst must not exist after a failed copy: %v", err)
	}

	// No leftover temp file in the directory (deferred cleanup ran).
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".copy-") {
			t.Errorf("leftover temp file after failed copy: %s", e.Name())
		}
	}
}

func TestCopyFileContents(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")

	// A payload larger than the 1 MiB fallback buffer so the buffered copy loops.
	want := bytes.Repeat([]byte("abox-"), 500_000) // ~2.5 MiB
	if err := os.WriteFile(src, want, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := CopyFile(src, dst); err != nil {
		t.Fatalf("CopyFile: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("copied contents differ: got %d bytes, want %d", len(got), len(want))
	}
}

func TestCopyFileOverwritesDestination(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")

	if err := os.WriteFile(src, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Pre-existing dst with different (longer) content must be fully replaced,
	// not partially overwritten.
	if err := os.WriteFile(dst, []byte("stale-and-longer"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := CopyFile(src, dst); err != nil {
		t.Fatalf("CopyFile: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("dst = %q, want %q", got, "new")
	}
}

func TestCopyFileRejectsSymlinkSource(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	dst := filepath.Join(dir, "dst")

	if err := os.WriteFile(target, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	// A symlinked source (e.g. from a crafted import archive) must be rejected
	// rather than followed.
	if err := CopyFile(link, dst); err == nil {
		t.Fatal("CopyFile must reject a symlink source")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatal("no destination should be created when the source is rejected")
	}
}

func TestCopyFileRejectsNonRegularSource(t *testing.T) {
	dir := t.TempDir()
	// A directory is not a regular file.
	if err := CopyFile(dir, filepath.Join(dir, "dst")); err == nil {
		t.Fatal("CopyFile must reject a directory source")
	}
}

func TestCopyFileMissingSource(t *testing.T) {
	dir := t.TempDir()
	if err := CopyFile(filepath.Join(dir, "nope"), filepath.Join(dir, "dst")); err == nil {
		t.Fatal("CopyFile must error when the source does not exist")
	}
}
