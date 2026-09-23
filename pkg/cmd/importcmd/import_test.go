package importcmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/pkg/cmd/export"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

// writeArchiveWithName builds a minimal .abox.tar.gz whose manifest names the
// instance, so runImport's manifest-derived name path can be exercised.
func writeArchiveWithName(t *testing.T, name string) string {
	t.Helper()
	manifest := export.Manifest{
		Version:  1,
		Format:   "abox-archive",
		Instance: export.ManifestInstance{Name: name},
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "in.abox.tar.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestImportRejectsInvalidManifestName is the LOW-4 regression: import must
// validate the (attacker-controlled) manifest instance name before it flows into
// filesystem paths, resource names, and config.Save — mirroring create. A name
// that fails ValidateInstanceName must be rejected up front.
func TestImportRejectsInvalidManifestName(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	opts := &Options{Factory: &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}}

	for _, bad := range []string{"../evil", "foo/bar", ".", "-leading", "has space"} {
		t.Run(bad, func(t *testing.T) {
			archive := writeArchiveWithName(t, bad)
			err := runImport(context.Background(), opts, archive, "")
			if err == nil {
				t.Fatalf("import must reject invalid instance name %q", bad)
			}
			if !strings.Contains(err.Error(), "instance name") {
				t.Errorf("error = %q, want an instance-name validation error", err)
			}
		})
	}
}

// TestVerifySnapshotBaseImage is the H-1 regression: the snapshot base-image
// pre-check must consult the SAME locations the rebase reads — the backend store
// (paths.BaseImages, derived from be.StorageDir()) and the user cache
// (paths.UserBaseImages, where `abox base pull` installs). The pre-relocation bug
// used config.GetPaths (default storage root ~/.local/share/abox/disks), a dead
// path that neither the rebase nor `base pull` ever populates, so valid snapshot
// imports were spuriously rejected with "base image not found".
func TestVerifySnapshotBaseImage(t *testing.T) {
	imageName := config.UserBaseImageName("ubuntu")

	newPaths := func(t *testing.T) *config.Paths {
		t.Helper()
		root := t.TempDir()
		p := &config.Paths{
			BaseImages:     filepath.Join(root, "store", "base"), // be.StorageDir()/base
			UserBaseImages: filepath.Join(root, "cache", "base"), // `base pull` destination
		}
		for _, d := range []string{p.BaseImages, p.UserBaseImages} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		return p
	}
	writeBase := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, imageName), []byte("qcow2"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("missing in both locations is rejected with a base-pull hint", func(t *testing.T) {
		p := newPaths(t)
		err := verifySnapshotBaseImage(p, "ubuntu")
		if err == nil {
			t.Fatal("expected an error when the base image is absent")
		}
		if !strings.Contains(err.Error(), "base image") {
			t.Errorf("error = %q, want a base-image-not-found error", err)
		}
		var hint *cmdutil.ErrHint
		if !errors.As(err, &hint) || !strings.Contains(hint.Hint, "base pull") {
			t.Errorf("expected an ErrHint pointing at `abox base pull`, got %v", err)
		}
	})

	t.Run("present in backend store is accepted", func(t *testing.T) {
		p := newPaths(t)
		writeBase(t, p.BaseImages)
		if err := verifySnapshotBaseImage(p, "ubuntu"); err != nil {
			t.Errorf("expected nil when base is in the backend store, got %v", err)
		}
	})

	t.Run("present only in user cache is accepted", func(t *testing.T) {
		p := newPaths(t)
		writeBase(t, p.UserBaseImages)
		if err := verifySnapshotBaseImage(p, "ubuntu"); err != nil {
			t.Errorf("expected nil when base is in the user cache, got %v", err)
		}
	})
}

// TestImportRejectsInvalidNewNameArg verifies the explicit --name argument is
// validated too (not just the manifest-derived name).
func TestImportRejectsInvalidNewNameArg(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	opts := &Options{Factory: &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}}

	archive := writeArchiveWithName(t, "good-name")
	err := runImport(context.Background(), opts, archive, "../evil")
	if err == nil {
		t.Fatal("import must reject an invalid --name argument")
	}
	if !strings.Contains(err.Error(), "instance name") {
		t.Errorf("error = %q, want an instance-name validation error", err)
	}
}

// writeTarGz builds a .tar.gz at a temp path from the given regular-file entries
// (name -> size), writing `size` zero bytes for each, and returns its path.
func writeTarGz(t *testing.T, entries []struct {
	name string
	size int64
}) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o600, Size: e.size, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if e.size > 0 {
			if _, err := tw.Write(make([]byte, e.size)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestExtractTarGz_Legitimate confirms a normal small archive still extracts.
func TestExtractTarGz_Legitimate(t *testing.T) {
	archive := writeTarGz(t, []struct {
		name string
		size int64
	}{{"config.yaml", 1024}, {"disk.qcow2", 4096}})

	dest := t.TempDir()
	if err := extractTarGz(archive, dest); err != nil {
		t.Fatalf("legitimate archive should extract, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "disk.qcow2")); err != nil {
		t.Errorf("expected extracted file: %v", err)
	}
}

// TestExtractTarGz_RejectsExcessiveEntryCount verifies the entry-count cap.
func TestExtractTarGz_RejectsExcessiveEntryCount(t *testing.T) {
	entries := make([]struct {
		name string
		size int64
	}, maxImportEntries+1)
	for i := range entries {
		entries[i] = struct {
			name string
			size int64
		}{name: filepath.Join("d", "f"+strconv.Itoa(i)), size: 0}
	}
	archive := writeTarGz(t, entries)
	err := extractTarGz(archive, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "entry count") {
		t.Fatalf("expected entry-count cap error, got %v", err)
	}
}

// TestExtractTarFile_RejectsNegativeSize verifies a malformed negative header
// size is rejected rather than mishandled.
func TestExtractTarFile_RejectsNegativeSize(t *testing.T) {
	var total int64
	h := &tar.Header{Name: "x", Mode: 0o600, Size: -1, Typeflag: tar.TypeReg}
	err := extractTarFile(tar.NewReader(bytes.NewReader(nil)), h, filepath.Join(t.TempDir(), "x"), &total)
	if err == nil || !strings.Contains(err.Error(), "negative size") {
		t.Fatalf("expected negative-size rejection, got %v", err)
	}
}

// TestExtractTarFile_RejectsOversizedHeader verifies the per-file cap rejects a
// header claiming more than maxImportFileBytes without attempting the copy.
func TestExtractTarFile_RejectsOversizedHeader(t *testing.T) {
	var total int64
	h := &tar.Header{Name: "big", Mode: 0o600, Size: maxImportFileBytes + 1, Typeflag: tar.TypeReg}
	err := extractTarFile(tar.NewReader(bytes.NewReader(nil)), h, filepath.Join(t.TempDir(), "big"), &total)
	if err == nil || !strings.Contains(err.Error(), "per-file cap") {
		t.Fatalf("expected per-file cap rejection, got %v", err)
	}
}
