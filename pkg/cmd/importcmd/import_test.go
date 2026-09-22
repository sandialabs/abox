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
